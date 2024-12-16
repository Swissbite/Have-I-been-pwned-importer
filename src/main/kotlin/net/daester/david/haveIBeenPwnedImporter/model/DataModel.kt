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

package net.daester.david.haveIBeenPwnedImporter.model

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.time.LocalDate
import java.time.LocalDateTime

typealias Suffix = String
typealias Prefix = String
typealias Checksum = String

/**
 * Data class representing a single file
 */
data class FileData(val prefix: Prefix, val hashesWithOccurrence: List<SuffixHashWithOccurrence>, val checksum: Checksum) {
    fun toSingleRecordHashesWithOccurrence(): List<SingleRecordHashWithOccurrence> =
        hashesWithOccurrence.map {
            SingleRecordHashWithOccurrence(
                prefix = prefix,
                suffix = it.suffix,
                occurrence = it.occurrence,
                fileChecksum = checksum,
            )
        }

    suspend fun toPrefixWithHashes(): PrefixWithHashes =
        coroutineScope {
            val asyncSum = async { hashesWithOccurrence.sumOf { it.occurrence.toLong() } }
            val asyncMin = async { hashesWithOccurrence.minBy { it.occurrence } }
            val asyncMax = async { hashesWithOccurrence.maxBy { it.occurrence } }
            PrefixWithHashes(
                prefix = prefix,
                hashes = hashesWithOccurrence,
                totalOccurrences = asyncSum.await(),
                maxHash = asyncMax.await(),
                minHash = asyncMin.await(),
                checksum = checksum,
            )
        }
}

data class SuffixHashWithOccurrence(val suffix: Suffix, val occurrence: Int) {
    companion object {
        /**
         * This companion object is a shortcut cheat to have typed mongoDB collection and out of box serialization
         * and - in addition - eliminate hard coded strings to access fields in the collection
         */
        val suffixFieldName = SuffixHashWithOccurrence::suffix.name
        val occurrenceFieldName = SuffixHashWithOccurrence::occurrence.name
    }
}

data class PrefixWithHashes(
    val prefix: Prefix,
    val hashes: List<SuffixHashWithOccurrence>,
    val totalOccurrences: Long,
    val maxHash: SuffixHashWithOccurrence,
    val minHash: SuffixHashWithOccurrence,
    val checksum: String,
    val lastUpdated: LocalDate = LocalDate.now(),
) {
    companion object {
        /**
         * This companion object is a shortcut cheat to have typed mongoDB collection and out of box serialization
         * and - in addition - eliminate hard coded strings to access fields in the collection
         */
        val prefixFieldName = PrefixWithHashes::prefix.name
        val hashesFieldName = PrefixWithHashes::hashes.name
        val totalOccurrencesFieldName = PrefixWithHashes::totalOccurrences.name
        val maxHashFieldName = PrefixWithHashes::maxHash.name
        val minHashFieldName = PrefixWithHashes::minHash.name
        val checksumFieldName = PrefixWithHashes::checksum.name
        val lastUpdatedFieldName = PrefixWithHashes::lastUpdated.name
    }
}

data class SingleRecordHashWithOccurrence(
    val prefix: Prefix,
    val suffix: Suffix,
    val occurrence: Int,
    val fileChecksum: Checksum,
    val lastUpdate: LocalDateTime? = LocalDateTime.now(),
) {
    companion object {
        /**
         * This companion object is a shortcut cheat to have typed mongoDB collection and out of box serialization
         */
        val prefixFieldName = SingleRecordHashWithOccurrence::prefix.name
        val suffixFieldName = SingleRecordHashWithOccurrence::suffix.name
        val occurrenceFieldName = SingleRecordHashWithOccurrence::occurrence.name
        val fileChecksum = SingleRecordHashWithOccurrence::fileChecksum.name
        val lastUpdate = SingleRecordHashWithOccurrence::lastUpdate.name
    }
}

data class ByPrefixStatistic(val validated: Int, val inserted: Int, val updated: Int, val deleted: Int)
