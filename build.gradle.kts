/*
 * Copyright (c) 2024 David Däster
 *
 * This file is part of "Have I been pwned - importer".
 *
 * "Have I been pwned - importer" is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free  Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * "Have I been pwned - importer" is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * "Have I been pwned - importer". If not, see <https://www.gnu.org/licenses/>.
 */

plugins {
    kotlin("jvm") version "2.4.21"
    application
    id("com.gradleup.shadow") version "9.6.1"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
    id("io.github.ben-manes.versions") version "0.67.0"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}
application {
    mainClass = "net.daester.david.haveIBeenPwnedImporter.MainKt"
}
dependencies {
    val logbackVersion = "1.6.6"
    val cliktVersion = "5.1.0"

    testImplementation(kotlin("test"))
    implementation("org.mongodb:mongodb-driver-kotlin-coroutine:5.14.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-core:1.12.0")
    implementation("io.github.oshai:kotlin-logging:8.0.6")
    implementation("org.mongodb:bson-kotlinx:5.14.0")
    // Used by the MongoDB driver's codecs at runtime; declared to keep it in line with the Kotlin version
    implementation(kotlin("reflect"))
    implementation("org.slf4j:slf4j-api:2.0.20")
    implementation("ch.qos.logback:logback-core:$logbackVersion")
    implementation("ch.qos.logback:logback-classic:$logbackVersion")
    implementation("com.github.ajalt.clikt:clikt:$cliktVersion")
    implementation("com.github.ajalt.clikt:clikt-markdown:$cliktVersion")
    implementation("com.squareup.okhttp3:okhttp:5.5.1")
}

tasks.shadowJar {
    archiveFileName.set("pwned.jar")
    archiveBaseName.set("pwned")

    minimize {
        // Needed at runtime by the MongoDB Kotlin driver (reflection-based codecs)
        exclude(dependency("org.jetbrains.kotlin:kotlin-reflect:.*"))
        // SLF4J loads the Logback provider via ServiceLoader; without this, logging falls back to NOP
        exclude(dependency("ch.qos.logback:logback-classic:.*"))
    }
}
tasks.startScripts {
    applicationName = "pwned"
}

tasks.startShadowScripts {
    applicationName = "pwned"
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}
