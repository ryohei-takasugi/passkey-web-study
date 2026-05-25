plugins {
    application
    eclipse
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    implementation(libs.vertx.web)
    implementation(libs.webauthn4j.core)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.logback.classic)
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {
    mainClass = "org.example.MainVerticle"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
