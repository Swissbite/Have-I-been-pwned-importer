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

import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import net.daester.david.haveIBeenPwnedImporter.commands.Download
import net.daester.david.haveIBeenPwnedImporter.commands.ImportByHash
import net.daester.david.haveIBeenPwnedImporter.commands.ImportByPrefix
import net.daester.david.haveIBeenPwnedImporter.commands.Pwned
import sun.misc.Signal
import kotlin.coroutines.cancellation.CancellationException

private val logger: KLogger = KotlinLogging.logger { }

fun main(args: Array<String>) =
    Pwned()
        .subcommands(
            Download(),
            ImportByPrefix(),
            ImportByHash(),
        ).main(args)

object RegisterToCancelOnSignalInt {
    private val jobsToCancel = MutableStateFlow(emptyList<Job>())
    private val channelsToCancel = MutableStateFlow(emptyList<ReceiveChannel<*>>())

    fun registerJobForIntSignal(job: Job) {
        jobsToCancel.update { it.plus(job) }
    }

    fun registerChannelForIntSignal(channel: ReceiveChannel<*>) {
        channelsToCancel.update { it.plus(channel) }
    }

    init {
        Signal.handle(Signal("INT")) {
            logger.info {
                "Received INT signal. Canceling ${jobsToCancel.value.size} jobs and ${channelsToCancel.value.size} channels."
            }
            for (job in jobsToCancel.value) {
                job.cancel(CancellationException("Received INT signal. Canceling signal."))
            }
            for (channel in channelsToCancel.value) {
                channel.cancel(CancellationException("Received INT signal. Canceling signal."))
            }
        }
    }
}
