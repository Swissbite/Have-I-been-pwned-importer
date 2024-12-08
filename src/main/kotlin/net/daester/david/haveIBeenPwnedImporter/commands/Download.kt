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
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.RegisterToCancelOnSignalInt
import net.daester.david.haveIBeenPwnedImporter.downloader.downloadOwnedPasswordRangeFileToPath
import net.daester.david.haveIBeenPwnedImporter.downloader.prefixChannel
import net.daester.david.haveIBeenPwnedImporter.maxRepeatLaunch
import java.nio.file.Path
import kotlin.math.pow

class Download : CliktCommand() {
    private val logger = KotlinLogging.logger {}
    private val cachePathOption by CachePathOption()

    init {
        context {
            helpFormatter = defaultHelpFormatter
        }
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
                        val downloads =
                            downloadOwnedPasswordRangeFileToPath(cachePathOption.passwordHashesDirectory, prefixes)
                        RegisterToCancelOnSignalInt.registerChannelForIntSignal(downloads)
                        async {
                            for (path in downloads) {
                                downloaded.update { it.inc() }
                            }
                        }
                    }.awaitAll()
                }

            RegisterToCancelOnSignalInt.registerChannelForIntSignal(prefixes)
            RegisterToCancelOnSignalInt.registerJobForIntSignal(downloadJob)
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

@OptIn(ExperimentalCoroutinesApi::class)
internal fun CoroutineScope.downloadParallel(cacheDirectory: Path): ReceiveChannel<Path> =
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
