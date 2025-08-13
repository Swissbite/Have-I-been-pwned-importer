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

package net.daester.david.haveIBeenPwnedImporter.commands

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.parameters.groups.provideDelegate
import com.mongodb.kotlin.client.coroutine.MongoClient
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.RegisterToCancelOnSignalInt
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import net.daester.david.haveIBeenPwnedImporter.downloader.downloadParallel
import net.daester.david.haveIBeenPwnedImporter.file.FileData
import net.daester.david.haveIBeenPwnedImporter.file.produceAllFilePaths
import net.daester.david.haveIBeenPwnedImporter.file.produceFileData
import net.daester.david.haveIBeenPwnedImporter.importer.byRecord.ImportByRecord
import net.daester.david.haveIBeenPwnedImporter.maxRepeatLaunch

class ImportByHash : CliktCommand() {
    init {
        context {
            helpFormatter = defaultHelpFormatter
        }
    }

    private val cachePathOption: CachePathOption by CachePathOption()
    private val importOptions: DBImportOption by DBImportOption()
    private val logger = KotlinLogging.logger {}

    override fun help(context: Context): String =
        """
        Import password hashes to MongoDB to a document by hash
           
        Creates a single document for each single hash.
        """.trimIndent()

    override fun run() {
        val mongoClient: MongoClient = MongoClient.create(importOptions.mongoDbConnectionURI)
        val mongoDB = mongoClient.getDatabase(importOptions.mongoDbDatabase)
        runBlocking(context = Dispatchers.Default) {
            val pathsChannel =
                when (importOptions.download) {
                    true -> downloadParallel(cachePathOption.passwordHashesDirectory)
                    false -> produceAllFilePaths(cachePathOption.passwordHashesDirectory)
                }
            val fileDataChannel = produceFileData(pathsChannel)
            val importerJob = importByRecord(mongoDB, fileDataChannel)
            RegisterToCancelOnSignalInt.registerChannelForIntSignal(pathsChannel)
            RegisterToCancelOnSignalInt.registerChannelForIntSignal(fileDataChannel)
            RegisterToCancelOnSignalInt.registerJobForIntSignal(importerJob)
            StatusObject.logStatusWhileJobIsRunning(importerJob)
        }
    }

    private fun CoroutineScope.importByRecord(
        mongoDB: MongoDatabase,
        fileChannel: ReceiveChannel<FileData>,
    ) = launch {
        val ibr = ImportByRecord(status = StatusObject, database = mongoDB)
        (1..maxRepeatLaunch)
            .map {
                async {
                    logger.info {
                        "Starting importByHash process: $it/$maxRepeatLaunch"
                    }
                    ibr.processHashFiles(fileChannel)
                }
            }.awaitAll()
    }
}
