/*
 * Copyright (c) 2024 David Däster
 *
 * This file is part of "Have I been pwned - importer".
 *
 * "Have I been pwned - importer" is free software: you can redistribute it
 * and/or modify it under the terms of the GNU Affero General Public License as
 * published by the Free  Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * "Have I been pwned - importer" is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License along
 * with "Have I been pwned - importer". If not, see <https://www.gnu.org/licenses/>.
 */

package net.daester.david.haveIBeenPwnedImporter.importer.byPrefix

import com.mongodb.client.model.Filters.eq
import com.mongodb.client.model.FindOneAndReplaceOptions
import com.mongodb.client.model.IndexModel
import com.mongodb.client.model.ReturnDocument
import com.mongodb.kotlin.client.coroutine.MongoCollection
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel.Factory.BUFFERED
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.Status
import net.daester.david.haveIBeenPwnedImporter.file.FileData
import net.daester.david.haveIBeenPwnedImporter.systemProcesses
import org.bson.BsonDocument
import org.bson.BsonElement
import org.bson.BsonInt32
import java.time.LocalDate
import kotlin.math.max
import kotlin.math.min

@OptIn(ExperimentalCoroutinesApi::class)
class ImportByPrefix(
    private val status: Status,
    database: MongoDatabase,
    prefixCollectionName: String = "prefixes",
) {
    private val logger: KLogger = KotlinLogging.logger {}
    private val prefixCollection: MongoCollection<PrefixWithHashes> =
        database.getCollection<PrefixWithHashes>(prefixCollectionName)

    init {
        logger.info {
            "Setup import by prefix. " +
                "database:${database.name}" +
                ", collection:$prefixCollectionName" +
                ", systemProcesses:$systemProcesses"
        }
        runBlocking { createMandatoryIndexes() }
    }

    /**
     * Processes each file within the channel and upsert it into the defined collection.
     * @param fileChannel The chanel for the path of the single files to import
     * @see ImportByPrefix
     */
    suspend fun processHashFiles(fileChannel: ReceiveChannel<FileData>) =
        coroutineScope {
            val dataToProcess = extractFileContent(fileChannel)
            upsertInDb(dataToProcess, prefixCollection)
        }

    private suspend fun createMandatoryIndexes() {
        prefixCollection
            .createIndexes(
                listOf(
                    prefixIndex,
                    totalOccurrenceIndex,
                    maxHashOccurrenceIndex,
                    minHashOccurrenceIndex,
                    lastUpdatedIndex,
                ),
            ).collect()
    }

    /**
     * Creates a new [ReceiveChannel] of [PrefixWithHashes] to be imported into db.
     */
    private fun CoroutineScope.extractFileContent(fileChannel: ReceiveChannel<FileData>): ReceiveChannel<PrefixWithHashes> =
        produce(
            capacity = BUFFERED,
        ) {
            for (fileData in fileChannel) {
                logger.trace { "Process hashes for ${fileData.prefix} with checksum ${fileData.checksum}" }
                val total = async { fileData.hashesWithOccurrence.sumOf { it.occurrence.toLong() } }
                val minHash =
                    async { fileData.hashesWithOccurrence.minBy { it.occurrence }.let { HashWithOccurrence(it.suffix, it.occurrence) } }
                val maxHash =
                    async { fileData.hashesWithOccurrence.maxBy { it.occurrence }.let { HashWithOccurrence(it.suffix, it.occurrence) } }
                val hashes = async { fileData.hashesWithOccurrence.map { HashWithOccurrence(it.suffix, it.occurrence) } }
                send(
                    PrefixWithHashes(
                        prefix = fileData.prefix,
                        hashes = hashes.await(),
                        totalOccurrences = total.await(),
                        minHash = minHash.await(),
                        maxHash = maxHash.await(),
                        checksum = fileData.checksum,
                    ),
                )
                status.increaseFileProcessed()
                status.increaseTotalHashes(fileData.hashesWithOccurrence.size)
            }
        }

    private suspend fun upsertInDb(
        dataObjects: ReceiveChannel<PrefixWithHashes>,
        prefixCollection: MongoCollection<PrefixWithHashes>,
    ) {
        for (dataObject in dataObjects) {
            upsertInDb(dataObject, prefixCollection)
        }
    }

    private suspend fun upsertInDb(
        dataObject: PrefixWithHashes,
        prefixCollection: MongoCollection<PrefixWithHashes>,
    ) {
        val result =
            prefixCollection
                .withDocumentClass<JustPrefixAndChecksum>()
                .find(
                    eq(PrefixWithHashes.prefixFieldName, dataObject.prefix),
                ).firstOrNull()
        when (result) {
            null -> {
                prefixCollection.insertOne(dataObject)
                status.increaseInsertedHashes(dataObject.hashes.size)
            }
            JustPrefixAndChecksum(dataObject.prefix, dataObject.checksum) ->
                status.increaseValidatedHashes(dataObject.hashes.size)
            else -> {
                val beforeReplace =
                    prefixCollection.findOneAndReplace(
                        eq(PrefixWithHashes.prefixFieldName, dataObject.prefix),
                        dataObject,
                        options =
                            FindOneAndReplaceOptions()
                                .returnDocument(ReturnDocument.BEFORE),
                    )
                val beforeSize = beforeReplace?.hashes?.size ?: 0
                val updateSize = dataObject.hashes.size

                val inserted = max(updateSize - beforeSize, 0)
                // Yes, this is not accurate. A replacement of hashes (AAA deleted, BBB added) is
                // not correct calculated
                val deleted = max(beforeSize - updateSize, 0)
                val updated = min(beforeSize, updateSize)

                status.increaseInsertedHashes(inserted)
                status.increaseUpdatedHashes(updated)
                status.increaseDeletedHashes(deleted)
            }
        }
    }

    companion object {
        private val prefixIndex =
            IndexModel(
                BsonDocument(listOf(BsonElement(PrefixWithHashes.prefixFieldName, BsonInt32(1)))),
            )
        private val totalOccurrenceIndex =
            IndexModel(
                BsonDocument(
                    listOf(
                        BsonElement(
                            HashWithOccurrence.occurrenceFieldName,
                            BsonInt32(-1),
                        ),
                    ),
                ),
            )
        private val maxHashOccurrenceIndex =
            IndexModel(
                BsonDocument(
                    listOf(
                        BsonElement(
                            "${PrefixWithHashes.maxHashFieldName}.${HashWithOccurrence.occurrenceFieldName}",
                            BsonInt32(1),
                        ),
                    ),
                ),
            )
        private val minHashOccurrenceIndex =
            IndexModel(
                BsonDocument(
                    listOf(
                        BsonElement(
                            "${PrefixWithHashes.minHashFieldName}.${HashWithOccurrence.occurrenceFieldName}",
                            BsonInt32(1),
                        ),
                    ),
                ),
            )
        private val lastUpdatedIndex =
            IndexModel(
                BsonDocument(
                    listOf(BsonElement(PrefixWithHashes.lastUpdatedFieldName, BsonInt32(-1))),
                ),
            )
    }
}

data class JustPrefixAndChecksum(
    val prefix: Prefix,
    val checksum: String,
)

typealias Prefix = String

typealias Suffix = String

data class PrefixWithHashes(
    val prefix: Prefix,
    val hashes: List<HashWithOccurrence>,
    val totalOccurrences: Long,
    val maxHash: HashWithOccurrence,
    val minHash: HashWithOccurrence,
    val checksum: String,
    val lastUpdated: LocalDate = LocalDate.now(),
) {
    companion object {
        val prefixFieldName = PrefixWithHashes::prefix.name
        val hashesFieldName = PrefixWithHashes::hashes.name
        val totalOccurrencesFieldName = PrefixWithHashes::totalOccurrences.name
        val maxHashFieldName = PrefixWithHashes::maxHash.name
        val minHashFieldName = PrefixWithHashes::minHash.name
        val checksumFieldName = PrefixWithHashes::checksum.name
        val lastUpdatedFieldName = PrefixWithHashes::lastUpdated.name
    }
}

data class HashWithOccurrence(
    val suffix: Suffix,
    val occurrence: Int,
) {
    companion object {
        val suffixFieldName = HashWithOccurrence::suffix.name
        val occurrenceFieldName = HashWithOccurrence::occurrence.name
    }
}
