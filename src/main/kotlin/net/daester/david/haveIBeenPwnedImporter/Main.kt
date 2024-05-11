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

package net.daester.david.haveIBeenPwnedImporter

import com.mongodb.kotlin.client.coroutine.MongoClient
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import mu.KLogger
import mu.KotlinLogging
import net.daester.david.haveIBeenPwnedImporter.importer.byPrefix.ImportByPrefix
import net.daester.david.haveIBeenPwnedImporter.importer.byRecord.ImportByRecord
import java.nio.file.Path
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.util.Locale
import kotlin.streams.asStream

private val systemProcesses = Runtime.getRuntime().availableProcessors()

private val logger: KLogger = KotlinLogging.logger { }

interface Status {
    fun increaseFilesQueued()

    fun increaseFilesRead()

    fun increaseValidatedHashes(increaseBy: Int = 1)

    fun increaseInsertedHashes(increaseBy: Int = 1)

    fun increaseDeletedHashes(increaseBy: Int = 1)

    fun increaseTotalHashes(increaseBy: Int = 1)

    fun increaseUpdatedHashes(increaseBy: Int = 1)
}

data class CurrentState(
    val filesQueued: Int = 0,
    val filesRead: Int = 0,
    val totalHashesCounter: Int = 0,
    val validatedHashesCounter: Int = 0,
    val updatedHashesCounter: Int = 0,
    val insertedHashesCounter: Int = 0,
    val deletedHashesCounter: Int = 0,
)

object StatusObject : Status {
    private val statusCurrentStateMutable = MutableStateFlow(CurrentState())
    val currentState = statusCurrentStateMutable.asStateFlow()

    override fun increaseFilesQueued() {
        statusCurrentStateMutable.update { status2 -> status2.copy(filesQueued = status2.filesQueued + 1) }
    }

    override fun increaseFilesRead() {
        statusCurrentStateMutable.update { status2 -> status2.copy(filesRead = status2.filesRead + 1) }
    }

    override fun increaseValidatedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { status2 -> status2.copy(validatedHashesCounter = status2.validatedHashesCounter + increaseBy) }
    }

    override fun increaseInsertedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { status2 -> status2.copy(insertedHashesCounter = status2.insertedHashesCounter + increaseBy) }
    }

    override fun increaseDeletedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { status2 -> status2.copy(deletedHashesCounter = status2.deletedHashesCounter + increaseBy) }
    }

    override fun increaseTotalHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { status2 -> status2.copy(totalHashesCounter = status2.totalHashesCounter + increaseBy) }
    }

    override fun increaseUpdatedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { status2 -> status2.copy(updatedHashesCounter = status2.updatedHashesCounter + increaseBy) }
    }
}

private val swissGermanLocale: Locale = Locale.of("gsw")

fun formatter(n: Int): String = DecimalFormat("#,###", DecimalFormatSymbols(swissGermanLocale)).format(n)

private fun createStatusLogMessage(status: CurrentState): String {
    val queuedFiles = formatter(status.filesQueued)
    val readFiles = formatter(status.filesRead)
    val countedObjects = formatter(status.totalHashesCounter)
    val validated = formatter(status.validatedHashesCounter)
    val inserted = formatter(status.insertedHashesCounter)
    val updated = formatter(status.updatedHashesCounter)
    val deleted = formatter(status.deletedHashesCounter)
    return "Queued Files: $queuedFiles" +
        " - Read files: $readFiles" +
        " - Processed Objects: $countedObjects" +
        " - Validated: $validated" +
        " - Inserted: $inserted" +
        " - Updated: $updated" +
        " - Deleted: $deleted"
}

enum class StorageVariant { SINGLE, GROUPED }

fun main(args: Array<String>) {
    val parser = ArgParser("Pwned Password Hash Importer")
    val passwordsDirectory by parser.option(ArgType.String, shortName = "p", description = "Passwords Directory").required()
    val mongoDbConnectionURL by parser.option(
        ArgType.String,
        shortName = "u",
        description = "MongoDB Connection URL",
    ).default("mongodb://admin:admin1234@localhost:27017")
    val mongoDbDatabase by parser.option(ArgType.String, shortName = "d", description = "MongoDB Database").default("pwnd")
    val storageVariant by parser.option(
        ArgType.Choice<StorageVariant>(),
        shortName = "s",
        description = "Storage Variant. Either by single hash (SINGLE) or grouped by prefix (GROUPED)",
    ).default(StorageVariant.GROUPED)
    parser.parse(args)

    val mongoClient: MongoClient = MongoClient.create(mongoDbConnectionURL)

    val mongoDB = mongoClient.getDatabase(mongoDbDatabase)

    runBlocking {
        launch(Dispatchers.IO) {
            val job =
                when (storageVariant) {
                    StorageVariant.SINGLE -> importByRecord(mongoDB, passwordsDirectory)
                    StorageVariant.GROUPED -> importByPrefix(mongoDB, passwordsDirectory)
                }
            logger.info {
                createStatusLogMessage(StatusObject.currentState.value)
            }
            while (job.isActive) {
                delay(1000)
                logger.info {
                    createStatusLogMessage(StatusObject.currentState.value)
                }
            }
        }
    }
}

private fun CoroutineScope.importByPrefix(
    mongoDB: MongoDatabase,
    path: String,
) = launch {
    val ibp = ImportByPrefix(status = StatusObject, database = mongoDB)
    val filesToRead = getAllFilePaths(Path.of(path))
    ibp.processHashFiles(filesToRead, this)
}

private fun CoroutineScope.importByRecord(
    mongoDB: MongoDatabase,
    path: String,
) = launch {
    val ibr = ImportByRecord(status = StatusObject, database = mongoDB)
    val filesToRead = getAllFilePaths(Path.of(path))
    ibr.processHashFiles(filesToRead, this)
}

private fun CoroutineScope.getAllFilePaths(path: Path): ReceiveChannel<Path> =
    produce(
        capacity = systemProcesses,
    ) {
        logger.info { "Path: ${path.toAbsolutePath()}" }
        val files = path.toFile().walk().maxDepth(1).asStream().parallel().filter { it.isFile }.map { it.toPath() }.iterator()
        while (files.hasNext()) {
            send(files.next())
            StatusObject.increaseFilesQueued()
            logger.debug { createStatusLogMessage(StatusObject.currentState.value) }
        }
    }
