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

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

interface Status {
    fun increaseFilesQueued()

    fun increaseFilesRead()

    fun increaseValidatedHashes(increaseBy: Int = 1)

    fun increaseInsertedHashes(increaseBy: Int = 1)

    fun increaseDeletedHashes(increaseBy: Int = 1)

    fun increaseTotalHashes(increaseBy: Int = 1)

    fun increaseUpdatedHashes(increaseBy: Int = 1)

    val currentStatusLogMessage: String
}

data class CurrentState(
    val filesQueued: Int = 0,
    val filesRead: Int = 0,
    val totalHashesCounter: Int = 0,
    val validatedHashesCounter: Int = 0,
    val updatedHashesCounter: Int = 0,
    val insertedHashesCounter: Int = 0,
    val deletedHashesCounter: Int = 0,
)

object StatusObject : Status {
    private val statusCurrentStateMutable = MutableStateFlow(CurrentState())
    private val currentState = statusCurrentStateMutable.asStateFlow()

    override fun increaseFilesQueued() {
        statusCurrentStateMutable.update { state -> state.copy(filesQueued = state.filesQueued + 1) }
    }

    override fun increaseFilesRead() {
        statusCurrentStateMutable.update { state -> state.copy(filesRead = state.filesRead + 1) }
    }

    override fun increaseValidatedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { state -> state.copy(validatedHashesCounter = state.validatedHashesCounter + increaseBy) }
    }

    override fun increaseInsertedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { state -> state.copy(insertedHashesCounter = state.insertedHashesCounter + increaseBy) }
    }

    override fun increaseDeletedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { state -> state.copy(deletedHashesCounter = state.deletedHashesCounter + increaseBy) }
    }

    override fun increaseTotalHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { state -> state.copy(totalHashesCounter = state.totalHashesCounter + increaseBy) }
    }

    override fun increaseUpdatedHashes(increaseBy: Int) {
        statusCurrentStateMutable.update { state -> state.copy(updatedHashesCounter = state.updatedHashesCounter + increaseBy) }
    }

    override val currentStatusLogMessage: String
        get() {
            val status = currentState.value
            val queuedFiles = intFormatter(status.filesQueued)
            val readFiles = intFormatter(status.filesRead)
            val countedObjects = intFormatter(status.totalHashesCounter)
            val validated = intFormatter(status.validatedHashesCounter)
            val inserted = intFormatter(status.insertedHashesCounter)
            val updated = intFormatter(status.updatedHashesCounter)
            val deleted = intFormatter(status.deletedHashesCounter)
            return "Queued Files: $queuedFiles" +
                " - Read files: $readFiles" +
                " - DB Entries Parsed: $countedObjects" +
                " - Validated: $validated" +
                " - Inserted: $inserted" +
                " - Updated: $updated" +
                " - Deleted: $deleted"
        }
}
