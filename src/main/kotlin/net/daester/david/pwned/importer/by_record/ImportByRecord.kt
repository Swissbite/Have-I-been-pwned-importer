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

package net.daester.david.pwned.importer.by_record

import com.mongodb.client.model.*
import com.mongodb.client.model.Filters.and
import com.mongodb.client.model.Filters.eq
import com.mongodb.kotlin.client.coroutine.MongoCollection
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import mu.KLogger
import mu.KotlinLogging
import net.daester.david.pwned.Status
import org.bson.BsonDocument
import org.bson.BsonElement
import org.bson.BsonInt32
import java.nio.file.Path
import java.time.LocalDateTime

class ImportByRecord (private val status: Status, database: MongoDatabase, hashesCollectionName: String = "hashes", private val systemProcesses: Int = Runtime.getRuntime().availableProcessors()) {
    private val logger: KLogger = KotlinLogging.logger {  }
    private val hashCollection: MongoCollection<HashWithOccurrence> = database.getCollection<HashWithOccurrence>(hashesCollectionName)
    private val prefixIndex = IndexModel(BsonDocument(listOf(BsonElement(HashWithOccurrence::prefix.name, BsonInt32(1)))))
    private val occurrenceIndex = IndexModel(BsonDocument(listOf(BsonElement(HashWithOccurrence::occurrence.name, BsonInt32(-1)))))
    private val maxCoroutineFn = systemProcesses * 20
    init {
        logger.info { "Setup import by record. database:${database.name}, collection:$hashesCollectionName, systemProcesses:$systemProcesses" }
    }
    suspend fun processHashFiles(fileChannel: ReceiveChannel<Path>, scope: CoroutineScope)
        {
            hashCollection.createIndexes(listOf(prefixIndex, occurrenceIndex)).collect()
            val dataToProcess = scope.extractFileContent(fileChannel)
            val entriesToUpsert = scope.calculateNeededUpsertDataObjects(dataToProcess,
                hashCollection
            )
            repeat(maxCoroutineFn) {
                scope.upsertHashes(entriesToUpsert, hashCollection)
            }
        }
    private fun CoroutineScope.extractFileContent(fileChannel: ReceiveChannel<Path>): ReceiveChannel<Pair<Prefix, Map<Hash, Int>>> =  produce(
        capacity = systemProcesses
    ) {
        for (path in fileChannel) {
            logger.trace {"START: extractFileContent for ${path.fileName}" }
            val prefix = path.fileName.toString().split(".")[0]
            send(prefix to path.toFile().readLines().associate { line ->
                val (suffix, amount) = line.split(":")
                "$prefix$suffix" to amount.toInt(10)
            })
            status.increaseFilesRead()
            logger.trace {"END: extractFileContent for ${path.fileName}" }
        }
    }



    private fun CoroutineScope.calculateNeededUpsertDataObjects(
        fileContent: ReceiveChannel<Pair<Prefix, Map<Hash, Int>>>,
        dataSourceCollection: MongoCollection<HashWithOccurrence>
    ): ReceiveChannel<ChangeObject> = produce(capacity = systemProcesses) {
        for ((prefix, data ) in fileContent) {
            logger.trace { "START: calculate upsert for prefix $prefix" }
            val toDelete = mutableListOf<HashWithOccurrence>()
            val toUpdate = mutableListOf<HashWithOccurrence>()
            val toInsert = mutableListOf<HashWithOccurrence>()
            val visitedHashes = mutableSetOf<Hash>()
            dataSourceCollection.find(eq(HashWithOccurrence::prefix.name, prefix)).collect {
                val occurrence = data[it.hash]
                when {
                    occurrence == null -> if (it.occurrence > 0) toDelete.add(it.copy(occurrence = 0))
                    occurrence != it.occurrence -> toUpdate.add(it.copy(occurrence = occurrence, lastUpdate = LocalDateTime.now()))
                }
                visitedHashes.add(it.hash)
            }
            data.entries.filterNot { visitedHashes.contains(it.key) }.forEach {
                toInsert.add(HashWithOccurrence(prefix = prefix, hash = it.key, occurrence = it.value))
            }
            if (toDelete.isNotEmpty() || toUpdate.isNotEmpty() || toInsert.isNotEmpty()) {
                send(ChangeObject(toDelete = toDelete.toList(), toInsert = toInsert.toList(), toUpdate = toUpdate.toList()))
            }
            status.increaseTotalHashes(data.size)

            status.increaseValidatedHashes(data.size - toDelete.size - toUpdate.size - toInsert.size)
            logger.trace { "END: calculate upsert for prefix $prefix" }
        }
    }

    private fun CoroutineScope.upsertHashes(dataObjectsToUpsertInBulk: ReceiveChannel<ChangeObject>, collection: MongoCollection<HashWithOccurrence>) = launch {
        for (hashesWithOccurrence in dataObjectsToUpsertInBulk) {
            val toDelete = hashesWithOccurrence.toDelete.map { DeleteOneModel<HashWithOccurrence>(and(eq(HashWithOccurrence::prefix.name, it.prefix), eq(HashWithOccurrence::hash.name, it.hash))) }
            val toInsert = hashesWithOccurrence.toInsert.map { InsertOneModel(it) }
            val toUpdate = hashesWithOccurrence.toUpdate.map { UpdateOneModel<HashWithOccurrence>(
                and(eq(HashWithOccurrence::prefix.name, it.prefix), eq(HashWithOccurrence::hash.name, it.hash)), listOf(
                    Updates.set(HashWithOccurrence::occurrence.name, it.occurrence), Updates.set(HashWithOccurrence::lastUpdate.name, it.lastUpdate))) }

            collection.bulkWrite(
                toDelete + toInsert + toUpdate,
                BulkWriteOptions().ordered(false)
            )
            status.increaseDeletedHashes(toDelete.size)
            status.increaseInsertedHashes(toInsert.size)
            status.increaseUpdatedHashes(toUpdate.size)
        }
    }
}

typealias Prefix = String
typealias Hash = String


data class HashWithOccurrence(
    val hash: Hash,
    val prefix: Prefix,
    val occurrence: Int,
    val lastUpdate: LocalDateTime? = LocalDateTime.now()
)

data class ChangeObject(
    val toInsert: List<HashWithOccurrence>,
    val toUpdate: List<HashWithOccurrence>,
    val toDelete: List<HashWithOccurrence>
)