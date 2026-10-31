/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * Pure-JVM row-store protocol layer for the clock calendar protocol (v4.3).
 * Kept free of Android dependencies so it builds and tests on a plain JVM;
 * :core wires it into the SyncManager via a thin delegating WebDavCollection.
 */
plugins {
    // kotlin-jvm is already on the build classpath (build-logic) — apply
    // without a version so Gradle uses the loaded one.
    id("org.jetbrains.kotlin.jvm")
    alias(libs.plugins.kotlin.serialization)
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.coroutines)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.ktor.client.core)
    implementation(libs.bitfire.dav4jvm)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.ktor.client.mock)
    testImplementation(libs.junit)
    testImplementation(libs.ktor.client.cio)
}
