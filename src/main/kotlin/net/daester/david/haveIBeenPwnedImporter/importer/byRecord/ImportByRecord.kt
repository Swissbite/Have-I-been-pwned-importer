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

@file:OptIn(ExperimentalCoroutinesApi::class)

package net.daester.david.haveIBeenPwnedImporter.importer.byRecord

import com.mongodb.client.model.Filters.and
import com.mongodb.client.model.Filters.eq
import com.mongodb.client.model.Filters.ne
import com.mongodb.client.model.IndexModel
import com.mongodb.client.model.InsertManyOptions
import com.mongodb.kotlin.client.coroutine.MongoCollection
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.Status
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import net.daester.david.haveIBeenPwnedImporter.file.FileData
import net.daester.david.haveIBeenPwnedImporter.systemProcesses
import org.bson.BsonDocument
import org.bson.BsonElement
import org.bson.BsonInt32
import java.time.LocalDateTime
import kotlin.math.abs

class ImportByRecord(
    private val status: Status = StatusObject,
    database: MongoDatabase,
    hashesCollectionName: String = "hashes",
) {
    private val logger: KLogger = KotlinLogging.logger { }
    private val hashCollection: MongoCollection<HashWithOccurrence> = database.getCollection<HashWithOccurrence>(hashesCollectionName)
    private val prefixIndex = IndexModel(BsonDocument(listOf(BsonElement(HashWithOccurrence.prefixFieldName, BsonInt32(1)))))
    private val occurrenceIndex = IndexModel(BsonDocument(listOf(BsonElement(HashWithOccurrence.occurrenceFieldName, BsonInt32(-1)))))
    private val fileRecordChecksum =
        IndexModel(BsonDocument(listOf(BsonElement(HashWithOccurrence.fileRecordChecksumFieldName, BsonInt32(1)))))
    private val insertManyOptions = InsertManyOptions().ordered(false).bypassDocumentValidation(true)

    init {
        logger.info {
            "Setup import by record. " +
                "database:${database.name}" +
                ", collection:$hashesCollectionName" +
                ", systemProcesses:$systemProcesses"
        }

        runBlocking {
            launch {
                hashCollection.createIndexes(listOf(prefixIndex, occurrenceIndex, fileRecordChecksum)).collect()
            }
        }
    }

    /**
     * Processing all file data and insert each hash as a single record.
     * @param fileChannel The chanel for the single file representative
     */
    suspend fun processHashFiles(fileChannel: ReceiveChannel<FileData>) =
        coroutineScope {
            for (fileData in fileChannel) {
                logger.trace { "Process hashes for ${fileData.prefix} with checksum ${fileData.checksum}" }
                val entriesCount =
                    async(Dispatchers.IO) {
                        logger.trace { "Counting entries for ${fileData.prefix} ${fileData.checksum}" }
                        hashCollection.countDocuments(
                            and(
                                eq(
                                    HashWithOccurrence.prefixFieldName,
                                    fileData.prefix,
                                ),
                                eq(HashWithOccurrence.fileRecordChecksumFieldName, fileData.checksum),
                            ),
                        )
                    }
                val deleted =
                    async(Dispatchers.IO) {
                        logger.trace { "Deleting entries for ${fileData.prefix} with checksum not equal ${fileData.checksum}" }
                        hashCollection
                            .deleteMany(
                                and(
                                    eq(HashWithOccurrence.prefixFieldName, fileData.prefix),
                                    ne(HashWithOccurrence.fileRecordChecksumFieldName, fileData.checksum),
                                ),
                            ).deletedCount
                    }

                if (fileData.hashesWithOccurrence.size.toLong() == entriesCount.await()) {
                    status.increaseValidatedHashes(fileData.hashesWithOccurrence.size)
                    status.increaseDeletedHashes(deleted.await().toInt())
                    status.increaseTotalHashes(fileData.hashesWithOccurrence.size)
                } else {
                    // Either a previous update did not complete, or the hash changed. For simplicity, we'll just drop existing and re-insert all of a file.
                    val prepareBulkInsert =
                        async(Dispatchers.Default) {
                            fileData.hashesWithOccurrence.map {
                                HashWithOccurrence(
                                    prefix = fileData.prefix,
                                    hash = it.suffix,
                                    occurrence = it.occurrence,
                                    fileRecordChecksum = fileData.checksum,
                                )
                            }
                        }
                    val deletedExisting =
                        hashCollection
                            .deleteMany(
                                eq(
                                    HashWithOccurrence.prefixFieldName,
                                    fileData.prefix,
                                ),
                            ).deletedCount

                    status.increaseTotalHashes(prepareBulkInsert.await().size)
                    hashCollection.insertMany(prepareBulkInsert.await(), insertManyOptions).wasAcknowledged()

                    val inserted = abs(fileData.hashesWithOccurrence.size - deletedExisting)
                    val updated = abs(fileData.hashesWithOccurrence.size - inserted)
                    val deltaDeleteExisting = abs(deletedExisting - updated)

                    status.increaseDeletedHashes(deleted.await().toInt() + deltaDeleteExisting.toInt())
                    status.increaseInsertedHashes(inserted.toInt())
                    status.increaseUpdatedHashes(updated.toInt())
                }
                status.increaseFileProcessed()
            }
        }
}

typealias Prefix = String
typealias Hash = String

data class HashWithOccurrence(
    val hash: Hash,
    val prefix: Prefix,
    val occurrence: Int,
    val lastUpdate: LocalDateTime? = LocalDateTime.now(),
    val fileRecordChecksum: String,
) {
    companion object {
        val prefixFieldName = HashWithOccurrence::prefix.name
        val hashFieldName = HashWithOccurrence::hash.name
        val occurrenceFieldName = HashWithOccurrence::occurrence.name
        val lastUpdateFieldName = HashWithOccurrence::lastUpdate.name
        val fileRecordChecksumFieldName = HashWithOccurrence::fileRecordChecksum.name
    }
}
