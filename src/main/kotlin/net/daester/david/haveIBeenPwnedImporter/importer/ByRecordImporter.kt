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
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.coroutineScope
import net.daester.david.haveIBeenPwnedImporter.StatusObject
import net.daester.david.haveIBeenPwnedImporter.db.ByRecordAccessLayer
import net.daester.david.haveIBeenPwnedImporter.model.FileData
import kotlin.math.abs

class ByRecordImporter(
    private val accessLayer: ByRecordAccessLayer,
    private val statusObject: StatusObject = StatusObject,
) : Importer {
    private val logger: KLogger = KotlinLogging.logger { }

    /**
     * Processing all file data and insert each hash as a single record.
     * @param fileChannel The chanel for the single file representative
     */
    override suspend fun processHashFiles(fileChannel: ReceiveChannel<FileData>) =
        coroutineScope {
            for (fileData in fileChannel) {
                logger.trace { "Process hashes for ${fileData.prefix} with checksum ${fileData.checksum}" }
                val entriesCount =
                    async {
                        logger.trace { "Counting entries for ${fileData.prefix} ${fileData.checksum}" }
                        accessLayer.countByPrefixAndChecksum(prefix = fileData.prefix, checksum = fileData.checksum)
                    }
                val deleted =
                    async {
                        logger.trace { "Deleting entries for ${fileData.prefix} with checksum not equal ${fileData.checksum}" }
                        accessLayer.deleteByPrefixAndNotMatchingChecksum(prefix = fileData.prefix, checksum = fileData.checksum)
                    }

                if (fileData.hashesWithOccurrence.size.toLong() == entriesCount.await()) {
                    statusObject.increaseValidatedHashes(fileData.hashesWithOccurrence.size)
                    statusObject.increaseDeletedHashes(deleted.await().toInt())
                    statusObject.increaseTotalHashes(fileData.hashesWithOccurrence.size)
                } else {
                    // Either a previous update did not complete, or the hash changed. For simplicity, we'll just drop existing and re-insert all of a file.
                    val prepareBulkInsert =
                        async {
                            fileData.toSingleRecordHashesWithOccurrence()
                        }
                    val deletedExisting =
                        accessLayer.deleteByPrefixAndNotMatchingChecksum(prefix = fileData.prefix, checksum = fileData.checksum)

                    statusObject.increaseTotalHashes(prepareBulkInsert.await().size)
                    accessLayer.insertBulk(prepareBulkInsert.await())

                    val inserted = abs(fileData.hashesWithOccurrence.size - deletedExisting)
                    val updated = abs(fileData.hashesWithOccurrence.size - inserted)
                    val deltaDeleteExisting = abs(deletedExisting - updated)

                    statusObject.increaseDeletedHashes(deleted.await().toInt() + deltaDeleteExisting.toInt())
                    statusObject.increaseInsertedHashes(inserted.toInt())
                    statusObject.increaseUpdatedHashes(updated.toInt())
                }
                statusObject.increaseFileProcessed()
            }
        }
}
