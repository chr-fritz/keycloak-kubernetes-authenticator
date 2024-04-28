plugins {
    `java-library`
}
val keycloakVersion = "24.0.3"
val lombokVersion = "1.18.32"
repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    implementation(platform("org.keycloak.bom:keycloak-adapter-bom:${keycloakVersion}"))
    implementation(platform("org.keycloak.bom:keycloak-misc-bom:${keycloakVersion}"))
    implementation(platform("org.keycloak.bom:keycloak-spi-bom:${keycloakVersion}"))
    compileOnlyApi("org.keycloak:keycloak-server-spi:${keycloakVersion}")
    compileOnlyApi("org.keycloak:keycloak-server-spi-private:${keycloakVersion}")
    implementation("org.keycloak:keycloak-services:${keycloakVersion}")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.mockito:mockito-junit-jupiter:5.11.0")
    testImplementation("org.assertj:assertj-core:3.25.3")
    testImplementation("jakarta.ws.rs:jakarta.ws.rs-api:3.1.0")
    testImplementation("org.glassfish.jersey.core:jersey-common:3.1.6")

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
