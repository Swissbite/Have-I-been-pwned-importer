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

package net.daester.david.haveIBeenPwnedImporter.db.mongo

import com.mongodb.client.model.Filters.and
import com.mongodb.client.model.Filters.eq
import com.mongodb.client.model.Filters.ne
import com.mongodb.client.model.FindOneAndReplaceOptions
import com.mongodb.client.model.IndexModel
import com.mongodb.client.model.InsertManyOptions
import com.mongodb.client.model.ReturnDocument
import com.mongodb.kotlin.client.coroutine.MongoClient
import com.mongodb.kotlin.client.coroutine.MongoCollection
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.db.ByPrefixAccessLayer
import net.daester.david.haveIBeenPwnedImporter.db.ByRecordAccessLayer
import net.daester.david.haveIBeenPwnedImporter.model.ByPrefixStatistic
import net.daester.david.haveIBeenPwnedImporter.model.Checksum
import net.daester.david.haveIBeenPwnedImporter.model.Prefix
import net.daester.david.haveIBeenPwnedImporter.model.PrefixWithHashes
import net.daester.david.haveIBeenPwnedImporter.model.SingleRecordHashWithOccurrence
import net.daester.david.haveIBeenPwnedImporter.model.SuffixHashWithOccurrence
import org.bson.BsonDocument
import org.bson.BsonElement
import org.bson.BsonInt32
import kotlin.math.max
import kotlin.math.min

private data object MDB {
    private lateinit var database: MongoDatabase

    fun setupDbConnection(
        connectionURI: String,
        dbName: String,
    ): MongoDatabase {
        if (!this::database.isInitialized) {
            val mdb = MongoClient.create(connectionURI)
            database = mdb.getDatabase(dbName)
        }
        return database
    }
}

class MongoDbByPrefixAccessLayer(private val connectionURI: String, private val dbName: String, private val collectionName: String) :
    ByPrefixAccessLayer {
    private val collection: MongoCollection<PrefixWithHashes>
    private val logger = KotlinLogging.logger { }

    init {
        logger.info { "Connecting to MongoDB: $connectionURI" }
        val database = MDB.setupDbConnection(connectionURI, dbName)

        collection = database.getCollection<PrefixWithHashes>(collectionName)
        runBlocking {
            logger.info { "Create indexes on collection: $collectionName" }
            createMandatoryIndexes()
        }
    }

    override suspend fun upsertByPrefix(dataObject: PrefixWithHashes): ByPrefixStatistic {
        val result =
            collection
                .withDocumentClass<JustPrefixAndChecksum>()
                .find(
                    eq(PrefixWithHashes.prefixFieldName, dataObject.prefix),
                )
                .firstOrNull()
        return when (result) {
            null -> {
                collection.insertOne(dataObject)
                ByPrefixStatistic(inserted = dataObject.hashes.size, validated = 0, updated = 0, deleted = 0)
            }
            JustPrefixAndChecksum(dataObject.prefix, dataObject.checksum) ->
                ByPrefixStatistic(validated = dataObject.hashes.size, inserted = 0, updated = 0, deleted = 0)
            else -> {
                val beforeReplace =
                    collection.findOneAndReplace(
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

                ByPrefixStatistic(validated = 0, inserted = inserted, deleted = deleted, updated = updated)
            }
        }
    }

    private suspend fun createMandatoryIndexes() {
        collection
            .createIndexes(
                listOf(
                    prefixIndex,
                    totalOccurrenceIndex,
                    maxHashOccurrenceIndex,
                    minHashOccurrenceIndex,
                    lastUpdatedIndex,
                ),
            )
            .collect()
    }

    companion object {
        operator fun invoke(
            connectionURI: String,
            dbName: String,
            collectionName: String?,
        ): MongoDbByPrefixAccessLayer =
            MongoDbByPrefixAccessLayer(
                connectionURI = connectionURI,
                dbName = dbName,
                collectionName = collectionName ?: "prefix",
            )

        private val prefixIndex =
            IndexModel(
                BsonDocument(listOf(BsonElement(PrefixWithHashes.prefixFieldName, BsonInt32(1)))),
            )
        private val totalOccurrenceIndex =
            IndexModel(
                BsonDocument(
                    listOf(
                        BsonElement(
                            PrefixWithHashes.totalOccurrencesFieldName,
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
                            "${PrefixWithHashes.maxHashFieldName}.${SuffixHashWithOccurrence.occurrenceFieldName}",
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
                            "${PrefixWithHashes.minHashFieldName}.${SuffixHashWithOccurrence.occurrenceFieldName}",
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

        private data class JustPrefixAndChecksum(val prefix: Prefix, val checksum: Checksum)
    }
}

class MongoDbByRecordAccessLayer private constructor(connectionURI: String, dbName: String, collectionName: String) :
    ByRecordAccessLayer {
        private val collection: MongoCollection<SingleRecordHashWithOccurrence>
        private val logger = KotlinLogging.logger { }

        init {
            logger.info { "Connecting to MongoDB: $connectionURI" }
            val database = MDB.setupDbConnection(connectionURI, dbName)
            collection = database.getCollection<SingleRecordHashWithOccurrence>(collectionName)
            runBlocking {
                logger.info { "Create indexes on collection: $collectionName" }
                collection.createIndexes(listOf(prefixIndex, occurrenceIndex, fileRecordChecksum)).collect()
            }
        }

        override suspend fun countByPrefixAndChecksum(
            prefix: Prefix,
            checksum: Checksum,
        ): Long =
            collection.countDocuments(
                and(eq(SingleRecordHashWithOccurrence.prefixFieldName, prefix), eq(SingleRecordHashWithOccurrence.fileChecksum, checksum)),
            )

        override suspend fun deleteByPrefixAndNotMatchingChecksum(
            prefix: Prefix,
            checksum: Checksum,
        ): Long =
            collection.deleteMany(
                and(eq(SingleRecordHashWithOccurrence.prefixFieldName, prefix), ne(SingleRecordHashWithOccurrence.fileChecksum, checksum)),
            ).deletedCount

        override suspend fun insertBulk(hashesWithOccurrence: List<SingleRecordHashWithOccurrence>) {
            collection.insertMany(hashesWithOccurrence, insertManyOptions)
        }

        companion object {
            operator fun invoke(
                connectionURI: String,
                dbName: String,
                collectionName: String? = "hashes",
            ): MongoDbByRecordAccessLayer =
                MongoDbByRecordAccessLayer(
                    connectionURI = connectionURI,
                    dbName = dbName,
                    collectionName = collectionName ?: "hashes",
                )

            // By default, bulk-inserts are ordered. But this reduces throughput.
            private val insertManyOptions = InsertManyOptions().ordered(false)

            private val prefixIndex =
                IndexModel(BsonDocument(listOf(BsonElement(SingleRecordHashWithOccurrence.prefixFieldName, BsonInt32(1)))))
            private val occurrenceIndex =
                IndexModel(BsonDocument(listOf(BsonElement(SingleRecordHashWithOccurrence.occurrenceFieldName, BsonInt32(-1)))))
            private val fileRecordChecksum =
                IndexModel(BsonDocument(listOf(BsonElement(SingleRecordHashWithOccurrence.fileChecksum, BsonInt32(1)))))
        }
    }
