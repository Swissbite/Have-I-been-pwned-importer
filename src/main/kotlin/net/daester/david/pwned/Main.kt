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
package net.daester.david.pwned

import com.mongodb.kotlin.client.coroutine.MongoClient
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import mu.KLogger
import mu.KotlinLogging
import net.daester.david.pwned.importer.by_record.ImportByRecord
import java.nio.file.Path
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.time.LocalDateTime
import java.util.*
import kotlin.streams.asStream
import kotlin.system.exitProcess

private val mongodbConnectionURL = System.getenv("MONGODB_CONNECTION_URL") ?: "mongodb://admin:admin1234@localhost:27017"
private val path = System.getenv("PWNED_PASSWORDS_DIRECTORY")
private val database = System.getenv("MONGODB_DATABASE") ?: "pwnd"
private val mongoClient: MongoClient = MongoClient.create(mongodbConnectionURL)

private val mongoDB = mongoClient.getDatabase(database)

private val systemProcesses = Runtime.getRuntime().availableProcessors()


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
interface Status {
    fun increaseQueued()
    fun increaseReadFiles()
    fun increaseValidated(increaseBy: Int = 1)
    fun increaseInserted(increaseBy: Int = 1)
    fun increaseDeleted(increaseBy: Int = 1)
    fun increaseObjects(increaseBy: Int = 1)
    fun increaseUpdated(increaseBy: Int = 1)
}

private object StatusObject: Status {
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
    override fun increaseQueued() {
        synchronized(this) {
            ++fileQueued
        }
    }
    override fun increaseReadFiles() {
        synchronized(this) {
            ++filesRead
        }
    }

    override fun increaseValidated(increaseBy: Int) {
        synchronized(this) {
            validatedCounter += increaseBy
        }
    }

    override fun increaseUpdated(increaseBy: Int) {
        synchronized(this) {
            updatedCounter += increaseBy
        }
    }

    override fun increaseInserted(increaseBy: Int) {
        synchronized(this) {
            insertedCounter += increaseBy
        }
    }

    override fun increaseDeleted(increaseBy: Int) {
        synchronized(this) {
            deletedCounter += increaseBy
        }
    }
    override fun increaseObjects(increaseBy: Int) {
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

fun main() {
    if (path == null) {
        logger.error { "Environment PWNED_PASSWORDS_DIRECTORY is not set. Exit" }
        exitProcess(1)
    }
    runBlocking {
        launch(Dispatchers.IO) {
            val ibr = ImportByRecord(status = StatusObject, database = mongoDB)
            val filesToRead = getAllFilePaths(Path.of(path))

            val ibrJob = ibr.processHashFiles(filesToRead, this)
            while (ibrJob.isActive) {
                logger.info {
                    createStatusLogMessage()
                }
                delay(1000)
            }
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
