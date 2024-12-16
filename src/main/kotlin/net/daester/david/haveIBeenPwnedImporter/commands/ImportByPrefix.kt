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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.RegisterToCancelOnSignalInt
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import net.daester.david.haveIBeenPwnedImporter.db.ByPrefixAccessLayer
import net.daester.david.haveIBeenPwnedImporter.db.mongo.MongoDbByPrefixAccessLayer
import net.daester.david.haveIBeenPwnedImporter.file.produceAllFilePaths
import net.daester.david.haveIBeenPwnedImporter.file.produceFileData
import net.daester.david.haveIBeenPwnedImporter.importer.ByPrefixImporter
import net.daester.david.haveIBeenPwnedImporter.maxRepeatLaunch
import net.daester.david.haveIBeenPwnedImporter.model.FileData

class ImportByPrefix : CliktCommand() {
    init {
        context {
            helpFormatter = defaultHelpFormatter
        }
    }

    private val cachePathOption: CachePathOption by CachePathOption()
    private val dbSettings by MongoDBSettings()

    override fun help(context: Context): String =
        """
        Import password hashes to MongoDB grouped by prefix
           
        Creates a single document by existing hash file in the defined cache directory.
        """.trimIndent()

    override fun run() {
        val accessLayer =
            MongoDbByPrefixAccessLayer(dbSettings.mongoDbConnectionURI, dbSettings.mongoDbDatabase, dbSettings.collectionName)

        runBlocking(context = Dispatchers.Default) {
            val pathsChannel = produceAllFilePaths(cachePathOption.passwordHashesDirectory)

            val fileDataChannel = produceFileData(pathsChannel)
            val importerJob =
                launch {
                    importByPrefix(accessLayer, fileDataChannel)
                }
            RegisterToCancelOnSignalInt.registerChannelForIntSignal(fileDataChannel)
            RegisterToCancelOnSignalInt.registerChannelForIntSignal(pathsChannel)
            RegisterToCancelOnSignalInt.registerJobForIntSignal(importerJob)
            StatusObject.logStatusWhileJobIsRunning(importerJob)
        }
    }

    private suspend fun importByPrefix(
        accessLayer: ByPrefixAccessLayer,
        fileChannel: ReceiveChannel<FileData>,
    ) = coroutineScope {
        val ibp = ByPrefixImporter(accessLayer = accessLayer)
        repeat(maxRepeatLaunch) {
            launch {
                ibp.processHashFiles(fileChannel)
            }
        }
    }
}
