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

package net.daester.david.haveIBeenPwnedImporter.importer

import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel.Factory.BUFFERED
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.coroutineScope
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import net.daester.david.haveIBeenPwnedImporter.db.ByPrefixAccessLayer
import net.daester.david.haveIBeenPwnedImporter.model.FileData
import net.daester.david.haveIBeenPwnedImporter.model.PrefixWithHashes

@OptIn(ExperimentalCoroutinesApi::class)
class ByPrefixImporter(
    private val accessLayer: ByPrefixAccessLayer,
) : Importer {
    private val logger: KLogger = KotlinLogging.logger {}

    /**
     * Processes each file within the channel and upsert it into the defined collection.
     * @param fileChannel The chanel for the path of the single files to import
     * @see ByPrefixImporter
     */
    override suspend fun processHashFiles(fileChannel: ReceiveChannel<FileData>) =
        coroutineScope {
            val dataToProcess = extractFileContent(fileChannel)
            upsertInDb(dataToProcess)
        }

    /**
     * Creates a new [ReceiveChannel] of [PrefixWithHashes] to be imported into db.
     */
    private fun CoroutineScope.extractFileContent(fileChannel: ReceiveChannel<FileData>): ReceiveChannel<PrefixWithHashes> =
        produce(
            capacity = BUFFERED,
        ) {
            for (fileData in fileChannel) {
                logger.trace { "Process hashes for ${fileData.prefix} with checksum ${fileData.checksum}" }
                send(
                    fileData.toPrefixWithHashes(),
                )
                StatusObject.increaseFileProcessed()
                StatusObject.increaseTotalHashes(fileData.hashesWithOccurrence.size)
            }
        }

    private suspend fun upsertInDb(dataObjects: ReceiveChannel<PrefixWithHashes>) {
        for (dataObject in dataObjects) {
            accessLayer.upsertByPrefix(dataObject)
        }
    }
}
