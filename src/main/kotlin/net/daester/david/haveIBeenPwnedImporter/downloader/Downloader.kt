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

package net.daester.david.haveIBeenPwnedImporter.downloader

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpRequestRetry
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.utils.io.core.isEmpty
import io.ktor.utils.io.core.readBytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import okhttp3.Dispatcher
import java.nio.file.Path
import kotlin.io.path.appendBytes
import kotlin.io.path.createFile
import kotlin.io.path.deleteIfExists

object Downloader {
    private val hexCubicRange = (0..<16 * 16 * 16).map { it.toString(16).padStart(3, '0').uppercase() }
    private val hexSquareRange = (0..<16 * 16).map { it.toString(16).padStart(2, '0').uppercase() }

    private val client =
        HttpClient(OkHttp) {

            engine {
                config {
                    dispatcher(
                        Dispatcher().apply {
                            maxRequestsPerHost = maxRequests
                        },
                    )
                    pipelining = true
                }
            }

            install(HttpRequestRetry) {
                retryOnServerErrors(10)
                retryOnException(100, true)
                exponentialDelay()
            }
        }

    @OptIn(ExperimentalCoroutinesApi::class)
    fun CoroutineScope.downloadToPath(path: Path): ReceiveChannel<Path> =
        produce(capacity = Int.MAX_VALUE) {
            hexSquareRange.map { first3Chars ->
                async(start = CoroutineStart.LAZY) {
                    hexCubicRange.map { last2Chars ->
                        async {
                            val prefix = "$first3Chars$last2Chars"
                            val outputPath = path.resolve("$prefix.txt")
                            client.prepareGet("https://api.pwnedpasswords.com/range/$prefix").execute { response ->
                                val channel = response.bodyAsChannel()
                                outputPath.deleteIfExists()
                                outputPath.createFile()
                                while (!channel.isClosedForRead) {
                                    val packet = channel.readRemaining(DEFAULT_BUFFER_SIZE.toLong())
                                    while (!packet.isEmpty) {
                                        outputPath.appendBytes(packet.readBytes())
                                    }
                                }
                                send(outputPath)
                                StatusObject.increaseFilesQueued()
                            }
                        }
                    }
                }
            }.forEach { deferred ->
                deferred.await().forEach {
                    it.await()
                }
            }
        }
}
