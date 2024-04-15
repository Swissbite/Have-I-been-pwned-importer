/**
 *      This file is part of "Have I been pwned - importer".
 *
 *     "Have I been pwned - importer" is free software: you can redistribute
 *     it and/or modify it under the terms of the GNU General Public License
 *     as published by the Free  Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     "Have I been pwned - importer" is distributed in the hope that it will
 *     be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *     of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *     General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License along
 *     with "Have I been pwned - importer". If not, see <https://www.gnu.org/licenses/>.
 */
@file:OptIn(ExperimentalCoroutinesApi::class)
package net.daester.david.pwned

import com.mongodb.client.model.*
import com.mongodb.client.model.Filters.and
import com.mongodb.client.model.Filters.eq
import com.mongodb.kotlin.client.coroutine.MongoClient
import com.mongodb.kotlin.client.coroutine.MongoCollection
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.flow.collect
import mu.KLogger
import mu.KotlinLogging
import org.bson.BsonDocument
import org.bson.BsonElement
import org.bson.BsonInt32
import java.nio.file.Path
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.time.LocalDateTime
import java.util.*
import kotlin.streams.asStream
import kotlin.system.exitProcess

private val mongodbConnectionURL = System.getenv("MONGODB_CONNECTION_URL") ?: "mongodb://admin:admin1234@localhost:27017"
private val path = System.getenv("PWNED_PASSWORDS_DIRECTORY")
private val mongoClient: MongoClient = MongoClient.create(mongodbConnectionURL)

private val mongoDB = mongoClient.getDatabase("pwnd")
private val hashCollection: MongoCollection<HashWithOccurrence> = mongoDB.getCollection<HashWithOccurrence>("hashes")

private val systemProcesses = Runtime.getRuntime().availableProcessors()

private val maxCoroutineFn = systemProcesses * 20
private val logger: KLogger = KotlinLogging.logger {  }

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

private object StatusObject {
    var fileQueued: Int = 0
        private set
    var filesRead: Int = 0
        private set

    var objectCounter: Int = 0
        private set
    var validatedCounter: Int = 0
        private set
    var updatedCounter: Int = 0
        private set
    var insertedCounter: Int = 0
        private set
    var deletedCounter: Int = 0
        private set
    fun increaseQueued() {
        synchronized(this) {
            ++fileQueued
        }
    }
    fun increaseReadFiles() {
        synchronized(this) {
            ++filesRead
        }
    }

    fun increaseValidated(increaseBy: Int = 1) {
        synchronized(this) {
            validatedCounter += increaseBy
        }
    }

    fun increaseUpdated(increaseBy: Int = 1) {
        synchronized(this) {
            updatedCounter += increaseBy
        }
    }

    fun increaseInserted(increaseBy: Int = 1) {
        synchronized(this) {
            insertedCounter += increaseBy
        }
    }

    fun increaseDeleted(increaseBy: Int = 1) {
        synchronized(this) {
            deletedCounter += increaseBy
        }
    }
    fun increaseObjects(increaseBy: Int = 1) {
        synchronized(this) {
            objectCounter += increaseBy
        }
    }
}


private val swissGermanLocale: Locale = Locale.of("gsw")
fun formatter(n: Int): String =
    DecimalFormat("#,###", DecimalFormatSymbols(swissGermanLocale)).format(n)

private fun createStatusLogMessage(): String {
    val queuedFiles = formatter(StatusObject.fileQueued)
    val readFiles = formatter(StatusObject.filesRead)
    val countedObjects = formatter(StatusObject.objectCounter)
    val validated = formatter(StatusObject.validatedCounter)
    val inserted = formatter(StatusObject.insertedCounter)
    val updated = formatter(StatusObject.updatedCounter)
    val deleted = formatter(StatusObject.deletedCounter)
    return "Queued Files: $queuedFiles - Read files: $readFiles - Processed Objects: $countedObjects - Validated: $validated - Inserted: $inserted - Updated: $updated - Deleted: $deleted"

}

@OptIn(DelicateCoroutinesApi::class)
fun main() {
    if (path == null) {
        logger.error { "Environment PWNED_PASSWORDS_DIRECTORY is not set. Exit" }
        exitProcess(1)
    }
    runBlocking {
        val prefixIndex = IndexModel(BsonDocument(listOf(BsonElement(HashWithOccurrence::prefix.name, BsonInt32(1)))))
        val occurrenceIndex = IndexModel(BsonDocument(listOf(BsonElement(HashWithOccurrence::occurrence.name, BsonInt32(-1)))))

        hashCollection.createIndexes(listOf(prefixIndex, occurrenceIndex)).collect()
        launch(Dispatchers.IO) {

            val filesToRead = getAllFilePaths(Path.of(path))
            val dataToProcess = extractFileContent(filesToRead)
            val entriesToUpsert = calculateNeededUpsertDataObjects(dataToProcess, hashCollection)
            repeat(maxCoroutineFn) {
                upsertHashes(entriesToUpsert, hashCollection)
            }
            val processStatus = async {
                while (!entriesToUpsert.isClosedForReceive ) {
                    logger.info {
                        createStatusLogMessage()
                    }

                    delay(1000)
                }
            }
            processStatus.await()
        }
    }
}


private fun CoroutineScope.getAllFilePaths(path: Path): ReceiveChannel<Path> =  produce(
    capacity = systemProcesses) {

    logger.info { "Path: ${path.toAbsolutePath()}" }
    val files = path.toFile().walk().maxDepth(1).asStream().parallel().filter { it.isFile }.map { it.toPath() }.iterator()
    while (files.hasNext()) {
        send(files.next())
        StatusObject.increaseQueued()
        logger.debug { createStatusLogMessage() }
    }
}

private fun CoroutineScope.extractFileContent(fileChannel: ReceiveChannel<Path>): ReceiveChannel<Pair<Prefix, Map<Hash, Int>>> =  produce(
    capacity = systemProcesses) {
    for (path in fileChannel) {
        logger.trace("START: extractFileContent for {}", path.fileName)
        val prefix = path.fileName.toString().split(".")[0]
        send(prefix to path.toFile().readLines().associate { line ->
            val (suffix, amount) = line.split(":")
            "$prefix$suffix" to amount.toInt(10)
        })
        StatusObject.increaseReadFiles()
        logger.trace("END: extractFileContent for {}", path.fileName)

        logger.debug { createStatusLogMessage() }
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
        StatusObject.increaseObjects(data.size)

        StatusObject.increaseValidated(data.size - toDelete.size - toUpdate.size - toInsert.size)
        logger.trace { "END: calculate upsert for prefix $prefix" }
    }
}


private fun CoroutineScope.upsertHashes(dataObjectsToUpsertInBulk: ReceiveChannel<ChangeObject>, collection: MongoCollection<HashWithOccurrence>) = launch {
    for (hashesWithOccurrence in dataObjectsToUpsertInBulk) {
        val toDelete = hashesWithOccurrence.toDelete.map { DeleteOneModel<HashWithOccurrence>(and(eq(HashWithOccurrence::prefix.name, it.prefix), eq(HashWithOccurrence::hash.name, it.hash))) }
        val toInsert = hashesWithOccurrence.toInsert.map { InsertOneModel(it) }
        val toUpdate = hashesWithOccurrence.toUpdate.map { UpdateOneModel<HashWithOccurrence>(and(eq(HashWithOccurrence::prefix.name, it.prefix), eq(HashWithOccurrence::hash.name, it.hash)), listOf(Updates.set(HashWithOccurrence::occurrence.name, it.occurrence), Updates.set(HashWithOccurrence::lastUpdate.name, it.lastUpdate))) }

        collection.bulkWrite(
            toDelete + toInsert + toUpdate,
            BulkWriteOptions().ordered(false)
        )
        StatusObject.increaseDeleted(toDelete.size)
        StatusObject.increaseInserted(toInsert.size)
        StatusObject.increaseUpdated(toUpdate.size)
        logger.debug { createStatusLogMessage() }
    }
}