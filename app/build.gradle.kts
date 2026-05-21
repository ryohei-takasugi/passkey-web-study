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
    implementation(libs.vertx.auth.webauthn4j)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.logback.classic)
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {
    mainClass = "org.example.App"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
