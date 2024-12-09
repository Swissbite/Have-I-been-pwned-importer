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

import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.daester.david.haveIBeenPwnedImporter.RegisterToCancelOnSignalInt
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import net.daester.david.haveIBeenPwnedImporter.defaultChannelCapacity
import net.daester.david.haveIBeenPwnedImporter.maxRepeatLaunch
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import kotlin.io.path.outputStream

private val logger: KLogger = KotlinLogging.logger { }

private val defaultClient =
    OkHttpClient.Builder().retryOnConnectionFailure(true).followRedirects(true).connectionPool(
        ConnectionPool(maxIdleConnections = 1000, keepAliveDuration = 5, timeUnit = TimeUnit.MINUTES),
    ).addInterceptor { chain ->
        val request = chain.request()
        var response = chain.proceed(request)
        var retryCounter = 0
        val retryLimit = 5
        while (!response.isSuccessful && retryCounter < retryLimit) {
            response.close()
            retryCounter = retryCounter.inc()
            runBlocking {
                delay(500L * retryCounter)
            }
            response = chain.proceed(request)
        }
        response
    }.addInterceptor {
        val request = it.request()
        logger.debug {
            "Call -> ${request.url.encodedPath}"
        }
        val response = it.proceed(request)
        logger.debug {
            "Res <-- Status ${response.code}"
        }
        response
    }.build()

@OptIn(ExperimentalCoroutinesApi::class)
fun CoroutineScope.downloadOwnedPasswordRangeFileToPath(
    path: Path,
    prefixes: ReceiveChannel<String>,
    client: OkHttpClient = defaultClient,
): ReceiveChannel<Path> =
    produce(capacity = defaultChannelCapacity, context = coroutineContext) {
        for (prefix in prefixes) {
            val outputPath = path.resolve("$prefix.txt")

            val url = Request.Builder().get().url("https://api.pwnedpasswords.com/range/$prefix").build()
            val call = client.newCall(url)

            call.execute().use { response ->
                if (response.isSuccessful) {
                    response.body?.byteStream().use { responseInputStream ->
                        if (responseInputStream != null) {
                            outputPath.outputStream(
                                StandardOpenOption.CREATE,
                                StandardOpenOption.TRUNCATE_EXISTING,
                                StandardOpenOption.WRITE,
                            ).use {
                                responseInputStream.copyTo(it)
                            }
                        }
                    }
                }
                send(outputPath)
                StatusObject.increaseFilesQueued()
            }
        }
    }

@OptIn(ExperimentalCoroutinesApi::class)
fun CoroutineScope.prefixChannel() =
    produce(context = this.coroutineContext) {
        repeat(16 * 16 * 16 * 16 * 16) {
            send(it.toString(16).padStart(5, '0').uppercase())
        }
    }

@OptIn(ExperimentalCoroutinesApi::class)
internal fun CoroutineScope.downloadParallel(cacheDirectory: Path): ReceiveChannel<Path> =
    produce(capacity = defaultChannelCapacity, context = coroutineContext) {
        val prefixes = prefixChannel()
        repeat(maxRepeatLaunch) {
            val downloadJob =
                launch {
                    val downloads =
                        downloadOwnedPasswordRangeFileToPath(cacheDirectory, prefixes)
                    RegisterToCancelOnSignalInt.registerChannelForIntSignal(downloads)
                    RegisterToCancelOnSignalInt.registerChannelForIntSignal(prefixes)
                    for (path in downloads) {
                        send(path)
                    }
                }
            RegisterToCancelOnSignalInt.registerJobForIntSignal(downloadJob)
        }
    }
