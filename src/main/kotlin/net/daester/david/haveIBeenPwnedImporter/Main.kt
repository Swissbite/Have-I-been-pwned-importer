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
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.core.installMordantMarkdown
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.output.HelpFormatter
import com.github.ajalt.clikt.output.MordantHelpFormatter
import com.github.ajalt.clikt.parameters.groups.OptionGroup
import com.github.ajalt.clikt.parameters.groups.provideDelegate
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.help
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import com.mongodb.kotlin.client.coroutine.MongoClient
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.utils.io.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.downloader.downloadOwnedPasswordRangeFileToPath
import net.daester.david.haveIBeenPwnedImporter.downloader.prefixChannel
import net.daester.david.haveIBeenPwnedImporter.file.FileData
import net.daester.david.haveIBeenPwnedImporter.file.produceAllFilePaths
import net.daester.david.haveIBeenPwnedImporter.file.produceFileData
import net.daester.david.haveIBeenPwnedImporter.importer.byPrefix.ImportByPrefix
import net.daester.david.haveIBeenPwnedImporter.importer.byRecord.ImportByRecord
import sun.misc.Signal
import java.nio.file.Path
import kotlin.math.pow

private val logger: KLogger = KotlinLogging.logger { }

fun main(args: Array<String>) = Pwned().subcommands(Download(), ImportByPrefix(), ImportByHash()).main(args)

private val defaultHelpFormatter: (context: Context) -> HelpFormatter = {
    MordantHelpFormatter(context = it, showDefaultValues = true, showRequiredTag = true)
}

class Pwned : CliktCommand() {
    init {
        installMordantMarkdown()
        context {
            helpFormatter = defaultHelpFormatter
        }
    }

    override fun help(context: Context): String =
        """
        Download hashes to folder and / or import to a MongoDB database
        
        - `download` - Only download to configured cache folder
        - `import-*` - Import to configured database with optional download to configured cache folder
        """.trimIndent()

    override fun run() = Unit
}

class CachePathOption : OptionGroup("Generic settings") {
    val passwordHashesDirectory: Path by option().path(
        mustExist = true,
        canBeFile = false,
        canBeDir = true,
        mustBeWritable = true,
        mustBeReadable = true,
    )
        .help("Existing writable and readable directory to cache password hashes").required()
}

class DBImportOption : OptionGroup("DB Import settings") {
    val mongoDbConnectionURL: String by option().default("mongodb://admin:admin1234@localhost:27017").help { "MongoDB connection url." }
    val mongoDbDatabase: String by option().default("pwnd").help { "MongoDB Database" }
    val download: Boolean by option("--download", "-d").flag(default = false).help {
        "If set, it will download all pwned passwords from https://haveibeenpwned.com/."
    }
}

class Download : CliktCommand() {
    private val cachePathOption by CachePathOption()

    init {
        installMordantMarkdown()
    }

    override fun help(context: Context): String =
        """
        Download hashes to folder
        
        Downloads all password hashes from https://haveibeenpwned.com/ and stores them in a folder.
        
        Currently, only SHA-1 format is supported. For more details about the API, 
        see [Downloading all Pwned Passwords hashes](https://haveibeenpwned.com/API/v3#PwnedPasswords).
        """.trimIndent()

    override fun run() {
        runBlocking(context = Dispatchers.IO) {
            val prefixes = prefixChannel()
            val downloaded = MutableStateFlow(0)
            val totalHashes = 16.0.pow(5).toInt()

            val downloadJob =
                launch {
                    logger.info { "Start downloads" }
                    (0..maxRepeatLaunch).map {
                        async {
                            for (path in downloadOwnedPasswordRangeFileToPath(cachePathOption.passwordHashesDirectory, prefixes)) {
                                downloaded.update { it.inc() }
                            }
                        }
                    }.awaitAll()
                }
            while (downloadJob.isActive) {
                delay(1000)
                logger.info {
                    "Downloaded ${downloaded.value} / $totalHashes hashes"
                }
            }

            logger.info {
                "Downloaded ${downloaded.value} / $totalHashes hashes"
            }
        }
    }
}

class ImportByPrefix : CliktCommand() {
    init {
        installMordantMarkdown()
        context {
            helpFormatter = defaultHelpFormatter
        }
    }

    private val cachePathOption: CachePathOption by CachePathOption()
    private val importOptions: DBImportOption by DBImportOption()

    override fun help(context: Context): String =
        """
        Import password hashes to MongoDB grouped by prefix
           
        Creates a single document by existing hash file in the defined cache directory.
        """.trimIndent()

    override fun run() {
        val mongoClient: MongoClient = MongoClient.create(importOptions.mongoDbConnectionURL)
        val mongoDB = mongoClient.getDatabase(importOptions.mongoDbDatabase)
        runBlocking(context = Dispatchers.Default) {
            val pathsChannel =
                when (importOptions.download) {
                    true -> downloadParallel(cachePathOption.passwordHashesDirectory)
                    false -> produceAllFilePaths(cachePathOption.passwordHashesDirectory)
                }

            val importerJob = importByPrefix(mongoDB, produceFileData(pathsChannel))
            registerIntSignalToCancelJob(importerJob)
            printStatus(importerJob)
        }
    }
}

class ImportByHash : CliktCommand() {
    init {
        installMordantMarkdown()
        context {
            helpFormatter = defaultHelpFormatter
        }
    }

    private val cachePathOption: CachePathOption by CachePathOption()
    private val importOptions: DBImportOption by DBImportOption()

    override fun help(context: Context): String =
        """
        Import password hashes to MongoDB to a document by hash
           
        Creates a single document for each single hash.
        """.trimIndent()

    override fun run() {
        val mongoClient: MongoClient = MongoClient.create(importOptions.mongoDbConnectionURL)
        val mongoDB = mongoClient.getDatabase(importOptions.mongoDbDatabase)
        runBlocking(context = Dispatchers.Default) {
            val pathsChannel =
                when (importOptions.download) {
                    true -> downloadParallel(cachePathOption.passwordHashesDirectory)
                    false -> produceAllFilePaths(cachePathOption.passwordHashesDirectory)
                }

            val importerJob = importByRecord(mongoDB, produceFileData(pathsChannel))
            registerIntSignalToCancelJob(importerJob)
            printStatus(importerJob)
        }
    }
}

private fun registerIntSignalToCancelJob(job: Job) {
    Signal.handle(Signal("INT")) {
        logger.info {
            "Received INT signal. Canceling job."
        }
        job.cancel(CancellationException("Received INT signal. Canceling job."))
        logger.info { "Bye :-)" }
    }
}

private suspend fun printStatus(job: Job) {
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

@OptIn(ExperimentalCoroutinesApi::class)
private fun CoroutineScope.downloadParallel(cacheDirectory: Path): ReceiveChannel<Path> =
    produce {
        val prefixes = prefixChannel()
        repeat(maxRepeatLaunch) {
            launch {
                for (path in downloadOwnedPasswordRangeFileToPath(cacheDirectory, prefixes)) {
                    send(path)
                }
            }
        }
    }

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
