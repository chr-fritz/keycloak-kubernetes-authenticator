plugins {
    `java-library`
}
val keycloakVersion = "24.0.2"
val lombokVersion = "1.18.32"
repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    implementation(platform("org.keycloak.bom:keycloak-adapter-bom:${keycloakVersion}"))
    implementation(platform("org.keycloak.bom:keycloak-misc-bom:${keycloakVersion}"))
    implementation(platform("org.keycloak.bom:keycloak-spi-bom:${keycloakVersion}"))
    compileOnly("org.keycloak:keycloak-server-spi:${keycloakVersion}")
    compileOnly("org.keycloak:keycloak-server-spi-private:${keycloakVersion}")
    compileOnly("org.keycloak:keycloak-services:${keycloakVersion}")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    compileOnly("org.projectlombok:lombok:${lombokVersion}")
    annotationProcessor("org.projectlombok:lombok:${lombokVersion}")
}

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}


tasks.named<Test>("test") {
    useJUnitPlatform()
}
