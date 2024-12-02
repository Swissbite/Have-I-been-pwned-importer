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
import io.ktor.utils.io.readRemaining
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.io.readByteArray
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import okhttp3.Dispatcher
import java.nio.file.Path
import kotlin.io.path.appendBytes
import kotlin.io.path.createFile
import kotlin.io.path.deleteIfExists

private val defaultClient =
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
fun CoroutineScope.downloadOwnedPasswordRangeFileToPath(
    path: Path,
    prefix: ReceiveChannel<String>,
    client: HttpClient = defaultClient,
): ReceiveChannel<Path> =
    produce {
        val outputPath = path.resolve("$prefix.txt")

        val deleteAsync =
            async {
                outputPath.deleteIfExists()
            }

        client.prepareGet("https://api.pwnedpasswords.com/range/$prefix").execute { response ->
            val channel = response.bodyAsChannel()
            deleteAsync.await()
            outputPath.createFile()
            while (!channel.isClosedForRead) {
                val packet = channel.readRemaining(DEFAULT_BUFFER_SIZE.toLong())
                while (!packet.exhausted()) {
                    outputPath.appendBytes(packet.readByteArray())
                }
            }
        }
        send(outputPath)
        StatusObject.increaseFilesQueued()
    }

@OptIn(ExperimentalCoroutinesApi::class)
fun CoroutineScope.prefixChannel() =
    produce {
        repeat(16 * 16 * 16 * 16 * 16) {
            send(it.toString(16).padStart(5, '0').uppercase())
        }
    }
