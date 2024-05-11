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

package net.daester.david.pwned.importer.byPrefix

import com.mongodb.client.model.Filters.eq
import com.mongodb.client.model.FindOneAndReplaceOptions
import com.mongodb.client.model.IndexModel
import com.mongodb.client.model.ReturnDocument
import com.mongodb.kotlin.client.coroutine.MongoCollection
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import mu.KLogger
import mu.KotlinLogging
import net.daester.david.pwned.Status
import org.bson.BsonDocument
import org.bson.BsonElement
import org.bson.BsonInt32
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalDate
import kotlin.math.max
import kotlin.math.min

@OptIn(ExperimentalCoroutinesApi::class)
class ImportByPrefix(
    private val status: Status,
    database: MongoDatabase,
    prefixCollectionName: String = "prefixes",
    private val systemProcesses: Int = Runtime.getRuntime().availableProcessors(),
) {
    private val logger: KLogger = KotlinLogging.logger { }
    private val prefixCollection: MongoCollection<PrefixWithHashes> = database.getCollection<PrefixWithHashes>(prefixCollectionName)
    private val prefixIndex = IndexModel(BsonDocument(listOf(BsonElement(PrefixWithHashes::prefix.name, BsonInt32(1)))))
    private val totalOccurrenceIndex = IndexModel(BsonDocument(listOf(BsonElement(PrefixWithHashes::totalOccurrences.name, BsonInt32(-1)))))
    private val maxHashOccurrenceIndex =
        IndexModel(
            BsonDocument(listOf(BsonElement("${PrefixWithHashes::maxHash.name}.${HashWithOccurrence::occurrence.name}", BsonInt32(1)))),
        )
    private val minHashOccurrenceIndex =
        IndexModel(
            BsonDocument(listOf(BsonElement("${PrefixWithHashes::minHash.name}.${HashWithOccurrence::occurrence.name}", BsonInt32(1)))),
        )
    private val maxCoroutineFn = systemProcesses * 20

    init {
        logger.info {
            "Setup import by prefix. " +
                "database:${database.name}" +
                ", collection:$prefixCollectionName" +
                ", systemProcesses:$systemProcesses"
        }
    }

    /**
     * Processes each file within the channel and upsert it into the defined collection.
     * @param fileChannel The chanel for the path of the single files to import
     * @param scope Needed [CoroutineScope] to launch multiple [Job]s within this suspended function
     * @see ImportByPrefix
     */
    suspend fun processHashFiles(
        fileChannel: ReceiveChannel<Path>,
        scope: CoroutineScope,
    ) {
        prefixCollection.createIndexes(listOf(prefixIndex, totalOccurrenceIndex, maxHashOccurrenceIndex, minHashOccurrenceIndex)).collect()
        val dataToProcess = scope.extractFileContent(fileChannel)
        repeat(maxCoroutineFn) {
            scope.launch {
                upsertInDb(dataToProcess, prefixCollection)
            }
        }
    }

    private fun CoroutineScope.extractFileContent(fileChannel: ReceiveChannel<Path>): ReceiveChannel<PrefixWithHashes> =
        produce(
            capacity = systemProcesses,
        ) {
            for (path in fileChannel) {
                logger.trace { "START: extractFileContent for ${path.fileName}" }
                val prefix = path.fileName.toString().split(".")[0]
                val hashesAsync =
                    async {
                        extractListOfHashes(path)
                    }
                val checksumAsync =
                    async {
                        calculateChecksum(path)
                    }
                val hashes = hashesAsync.await()
                val checksum = checksumAsync.await()

                send(
                    PrefixWithHashes(
                        prefix = prefix,
                        hashes = hashes,
                        totalOccurrences =
                            hashes.sumOf {
                                it.occurrence
                            },
                        minHash = hashes.minBy { it.occurrence },
                        maxHash = hashes.maxBy { it.occurrence },
                        checksum = checksum,
                    ),
                )

                status.increaseFilesRead()
                status.increaseTotalHashes(hashes.size)
                logger.trace { "END: extractFileContent for ${path.fileName}" }
            }
        }

    private fun extractListOfHashes(path: Path): List<HashWithOccurrence> =
        path.toFile().readLines().map { line ->
            val (suffix, amount) = line.split(":")
            HashWithOccurrence(suffix = suffix, occurrence = amount.toLong())
        }

    @OptIn(ExperimentalStdlibApi::class)
    private fun calculateChecksum(path: Path): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(path.toFile().readBytes())
        return digest.toHexString()
    }

    private suspend fun upsertInDb(
        dataObjects: ReceiveChannel<PrefixWithHashes>,
        prefixCollection: MongoCollection<PrefixWithHashes>,
    ) {
        for (dataObject in dataObjects) {
            val result =
                prefixCollection.withDocumentClass<JustPrefixAndChecksum>().find(
                    eq(PrefixWithHashes::prefix.name, dataObject.prefix),
                ).firstOrNull()
            when (result) {
                null -> {
                    prefixCollection.insertOne(dataObject)
                    status.increaseInsertedHashes(dataObject.hashes.size)
                }
                JustPrefixAndChecksum(dataObject.prefix, dataObject.checksum) -> status.increaseValidatedHashes(dataObject.hashes.size)
                else -> {
                    val beforeReplace =
                        prefixCollection.findOneAndReplace(
                            eq(PrefixWithHashes::prefix.name, dataObject.prefix),
                            dataObject,
                            options = FindOneAndReplaceOptions().returnDocument(ReturnDocument.BEFORE),
                        )
                    val beforeSize = beforeReplace?.hashes?.size ?: 0
                    val updateSize = dataObject.hashes.size

                    val inserted = max(updateSize - beforeSize, 0)
                    // Yes, this is not accurate. A replacement of hashes (AAA deleted, BBB added) is not correct calculated
                    val deleted = max(beforeSize - updateSize, 0)
                    val updated = min(beforeSize, updateSize)

                    status.increaseInsertedHashes(inserted)
                    status.increaseUpdatedHashes(updated)
                    status.increaseDeletedHashes(deleted)
                }
            }
        }
    }
}

data class JustPrefixAndChecksum(val prefix: Prefix, val checksum: String)

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
)

data class HashWithOccurrence(val suffix: Suffix, val occurrence: Long)
