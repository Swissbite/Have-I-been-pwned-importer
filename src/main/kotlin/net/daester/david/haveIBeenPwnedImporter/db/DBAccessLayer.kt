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

package net.daester.david.haveIBeenPwnedImporter.db

import net.daester.david.haveIBeenPwnedImporter.model.ByPrefixStatistic
import net.daester.david.haveIBeenPwnedImporter.model.Checksum
import net.daester.david.haveIBeenPwnedImporter.model.Prefix
import net.daester.david.haveIBeenPwnedImporter.model.PrefixWithHashes
import net.daester.david.haveIBeenPwnedImporter.model.SingleRecordHashWithOccurrence

interface ByRecordAccessLayer {
    /**
     * Count entries by prefix and checksum
     * @return number of entries
     */
    suspend fun countByPrefixAndChecksum(
        prefix: Prefix,
        checksum: Checksum,
    ): Long

    /**
     * Deletes entries by prefix where the checksum does not match
     * @return number of deleted entries
     */
    suspend fun deleteByPrefixAndNotMatchingChecksum(
        prefix: Prefix,
        checksum: Checksum,
    ): Long

    /**
     * Insert entries
     * @return number of inserted entries
     */
    suspend fun insertBulk(hashesWithOccurrence: List<SingleRecordHashWithOccurrence>)
}

interface ByPrefixAccessLayer {
    suspend fun upsertByPrefix(dataObject: PrefixWithHashes): ByPrefixStatistic
}
