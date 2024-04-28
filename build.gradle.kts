plugins {
    jacoco
    `java-library`
    `maven-publish`
    id("com.palantir.git-version") version "3.0.0" // to compute the project version from Git tags and hashes
    id("org.sonarqube") version "5.0.0.4638"
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

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        html.required = true
        xml.required = true
    }
}
tasks.test {
    finalizedBy(tasks.jacocoTestReport) // report is always generated after tests run
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

sonar {
    properties {
        property("sonar.projectKey", "chr-fritz_keycloak-kubernetes-authenticator")
        property("sonar.organization", "chr-fritz")
    }
}

val gitVersion: groovy.lang.Closure<String> by extra
val versionDetails: groovy.lang.Closure<com.palantir.gradle.gitversion.VersionDetails> by extra
val details = versionDetails()
version = gitVersion() + (if (!details.isCleanTag) "-SNAPSHOT" else "")

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = "de.chrfritz.keycloak.authenticators"
            from(components["java"])
            artifactId = tasks.jar.get().archiveBaseName.get()
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url =
                uri("https://maven.pkg.github.com/" + System.getenv("GITHUB_ACTOR") + "/keycloak-kubernetes-authenticator")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
