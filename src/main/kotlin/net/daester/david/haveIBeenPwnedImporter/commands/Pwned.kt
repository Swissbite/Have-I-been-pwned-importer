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

package net.daester.david.haveIBeenPwnedImporter.commands

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.output.HelpFormatter
import com.github.ajalt.clikt.output.MordantMarkdownHelpFormatter

internal val defaultHelpFormatter: (context: Context) -> HelpFormatter = {
    MordantMarkdownHelpFormatter(context = it, showDefaultValues = true, showRequiredTag = true)
}

class Pwned : CliktCommand() {
    init {

        context {
            helpFormatter = defaultHelpFormatter
        }
    }

    override fun help(context: Context): String =
        """
        Download hashes to folder and / or import to a MongoDB database
        
        - `download` - Only download to configured cache folder
        - `import-*` - Import to configured database with optional download to configured cache folder
        """.trimIndent()

    override fun run() = Unit
}
