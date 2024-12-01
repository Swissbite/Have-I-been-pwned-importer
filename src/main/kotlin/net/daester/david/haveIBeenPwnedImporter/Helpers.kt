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

import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.util.Locale

val systemProcesses = Runtime.getRuntime().availableProcessors()
val maxRepeatLaunch = systemProcesses * 20
val defaultChannelCapacity = systemProcesses * 1000

val swissGermanLocale: Locale = Locale.of("gsw")

fun intFormatter(n: Int): String = DecimalFormat("#,###", DecimalFormatSymbols(swissGermanLocale)).format(n)