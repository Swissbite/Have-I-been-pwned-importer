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

package net.daester.david.haveIBeenPwnedImporter

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.help
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.prompt
import com.github.ajalt.clikt.parameters.types.boolean
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.path
import com.mongodb.kotlin.client.coroutine.MongoClient
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.utils.io.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.downloader.Downloader.downloadToPath
import net.daester.david.haveIBeenPwnedImporter.file.FileData
import net.daester.david.haveIBeenPwnedImporter.file.produceAllFilePaths
import net.daester.david.haveIBeenPwnedImporter.file.produceFileData
import net.daester.david.haveIBeenPwnedImporter.importer.byPrefix.ImportByPrefix
import net.daester.david.haveIBeenPwnedImporter.importer.byRecord.ImportByRecord
import sun.misc.Signal
import java.nio.file.Path

private val logger: KLogger = KotlinLogging.logger { }

enum class StorageVariant { SINGLE, GROUPED }

class Importer : CliktCommand() {
    private val passwordsDirectory: Path by option().path().help("Passwords Directory").prompt("Enter directory to cache passwords")
    private val mongoDbConnectionURL: String by option().prompt("MongoDB Connection URL", "mongodb://admin:admin1234@localhost:27017")
    private val mongoDbDatabase: String by option().prompt("MongoDB Database", "pwnd")
    private val storageVariant: StorageVariant by option().enum<StorageVariant>().prompt(
        "Storage Variant. Either by single hash (SINGLE) or grouped by prefix (GROUPED)",
        StorageVariant.GROUPED,
    )
    private val shouldUpdateFromInternet: Boolean by option().boolean().prompt("Should pwned passwords be updated from internet?", false)

    override fun run() {
        val mongoClient: MongoClient = MongoClient.create(mongoDbConnectionURL)
        val mongoDB = mongoClient.getDatabase(mongoDbDatabase)
        runBlocking {
            val job =
                launch(Dispatchers.Default) {
                    val pathsChannel =
                        when (shouldUpdateFromInternet) {
                            true -> downloadToPath(passwordsDirectory)
                            false -> produceAllFilePaths(passwordsDirectory)
                        }
                    val fileRead = produceFileData(pathsChannel)
                    val job =
                        when (storageVariant) {
                            StorageVariant.SINGLE -> importByRecord(mongoDB, fileRead)
                            StorageVariant.GROUPED -> importByPrefix(mongoDB, fileRead)
                        }
                    logger.info {
                        StatusObject.currentStatusLogMessage
                    }
                    while (job.isActive) {
                        delay(1000)
                        logger.info {
                            StatusObject.currentStatusLogMessage
                        }
                    }
                    while (!job.isCancelled && !job.isCompleted) {
                        logger.info {
                            StatusObject.currentStatusLogMessage
                        }
                    }
                    logger.info {
                        StatusObject.currentStatusLogMessage
                    }
                    logger.info {
                        "Job finished. Cleaning up JVM resources."
                    }
                    logger.info {
                        "Thank you. :-)"
                    }
                }
            Signal.handle(Signal("INT")) {
                logger.info {
                    "Received INT signal. Canceling job."
                }
                job.cancel(CancellationException("Received INT signal. Canceling job."))
                logger.info { "Bye :-)" }
            }
        }
    }
}

fun main(args: Array<String>) = Importer().main(args)

private fun CoroutineScope.importByPrefix(
    mongoDB: MongoDatabase,
    fileChannel: ReceiveChannel<FileData>,
) = launch {
    val ibp = ImportByPrefix(status = StatusObject, database = mongoDB)
    (0..maxRepeatLaunch).map {
        async {
            logger.info {
                "Starting importByPrefix process: $it"
            }
            ibp.processHashFiles(fileChannel, this)
        }
    }.awaitAll()
}

private fun CoroutineScope.importByRecord(
    mongoDB: MongoDatabase,
    fileChannel: ReceiveChannel<FileData>,
) = launch {
    val ibr = ImportByRecord(status = StatusObject, database = mongoDB)
    (0..maxRepeatLaunch).map {
        async {
            logger.info {
                "Starting importByHash process: $it"
            }
            ibr.processHashFiles(fileChannel, this)
        }
    }.awaitAll()
}
