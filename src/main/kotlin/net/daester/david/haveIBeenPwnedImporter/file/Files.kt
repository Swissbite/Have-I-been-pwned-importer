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

package net.daester.david.haveIBeenPwnedImporter.file

import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.produceIn
import kotlinx.coroutines.launch
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import net.daester.david.haveIBeenPwnedImporter.defaultChannelCapacity
import net.daester.david.haveIBeenPwnedImporter.maxRepeatLaunch
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.io.path.bufferedReader
import kotlin.streams.asStream

typealias Prefix = String
typealias Suffix = String

private val logger = KotlinLogging.logger { }

private fun getAllFilePathsAsFlow(path: Path): Flow<Path> =
    flow {
        logger.info { "Path: ${path.toAbsolutePath()}" }
        val files =
            path
                .toFile()
                .walk()
                .maxDepth(1)
                .asStream()
                .parallel()
                .filter { it.isFile }
                .map { it.toPath() }
                .iterator()
        while (files.hasNext()) {
            emit(files.next())
            StatusObject.increaseFilesQueued()
            logger.debug { StatusObject.currentStatusLogMessage }
        }
    }

fun CoroutineScope.produceAllFilePaths(path: Path): ReceiveChannel<Path> =
    getAllFilePathsAsFlow(path)
        .buffer(defaultChannelCapacity)
        .produceIn(this)

@OptIn(ExperimentalCoroutinesApi::class, ExperimentalStdlibApi::class)
fun CoroutineScope.produceFileData(fileChannel: ReceiveChannel<Path>): ReceiveChannel<FileData> =
    produce(capacity = defaultChannelCapacity) {
        repeat(maxRepeatLaunch) {
            launch(context = Dispatchers.IO) {
                for (path in fileChannel) {
                    val md = MessageDigest.getInstance("SHA-1")

                    val prefix = path.fileName.toString().split(".")[0]
                    md.update(prefix.toByteArray())
                    val hashes =
                        path.bufferedReader().useLines { lineSequence ->

                            lineSequence
                                .map { it.split(":") }
                                .filter { it.size == 2 }
                                .map {
                                    when (val occurrence = it[1].toIntOrNull()) {
                                        null -> {
                                            null
                                        }

                                        else -> {
                                            HashWithOccurrence(suffix = it[0], occurrence = occurrence)
                                                .also { md.update("${it.suffix}:${it.occurrence}".toByteArray()) }
                                        }
                                    }
                                }.filterNotNull()
                                .toList()
                        }

                    val checksum = md.digest().toHexString(HexFormat.UpperCase)

                    send(FileData(prefix = prefix, hashesWithOccurrence = hashes, checksum = checksum))
                    StatusObject.increaseFilesRead()
                }
            }
        }
    }

data class FileData(
    val prefix: Prefix,
    val hashesWithOccurrence: List<HashWithOccurrence>,
    val checksum: String,
)

data class HashWithOccurrence(
    val suffix: Suffix,
    val occurrence: Int,
)
