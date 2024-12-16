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

import com.github.ajalt.clikt.parameters.groups.OptionGroup
import com.github.ajalt.clikt.parameters.options.check
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.help
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import java.nio.file.Path

class CachePathOption : OptionGroup("Generic settings") {
    val passwordHashesDirectory: Path by option("--password-hashes-directory", "--cache-dir", "--dir").path(
        mustExist = true,
        canBeFile = false,
        canBeDir = true,
        mustBeWritable = true,
        mustBeReadable = true,
    )
        .help("Existing writable and readable directory to cache password hashes").required()
}

sealed class DBSettings(name: String) : OptionGroup(name)

class MongoDBSettings : DBSettings("MongoDB Database settings") {
    val mongoDbConnectionURI: String by option(
        "--mongodb-connection-uri",
        "--uri",
    ).default("mongodb://admin:admin1234@localhost:27017").help {
        "MongoDB connection url."
    }
    val mongoDbDatabase: String by option("--mongo-database").default("pwnd").help { "MongoDB Database" }

    val collectionName: String? by option("--collection-name").help { "MongoDB Collection" }
}

class MariaDBSettings : DBSettings("MariaDB Database settings") {
    val mariaDbHost: String by option(
        "--mariadb-host",
        "--host",
    ).default("localhost:3306").help {
        "MariaDB host with port."
    }.check(lazyMessage = {
        "Must contain host name and port. See default value as example"
    }) { it.split(":").size == 2 && it.split("/").size == 1 }
    val mariadbDatabase: String by option("--mariadb-database").default("pwned").help { "MariaDB Database" }
    val mariadbUser: String by option("--mariadb-user", "--user").default("pwned").help { "MariaDB User" }
    val mariadbPassword: String by option("--mariadb-password", "--password").default("pwned").help { "MariaDB Password" }
}
