import java.net.URLEncoder

plugins {
    jacoco
    `java-library`
    `maven-publish`
    id("com.palantir.git-version") version "3.1.0" // to compute the project version from Git tags and hashes
    id("org.sonarqube") version "5.1.0.4882"
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

val keycloakVersion = "25.0.5"
val lombokVersion = "1.18.34"
val guavaVersion = "33.3.0-jre"
val jUnitJupiterVersion = "5.11.0"
val mockitoJunitVersion = "5.13.0"
val assertJVersion = "3.26.3"
val jakartaWsRsVersion = "3.1.0"
val jerseyVersion = "3.1.8"
val commonsCodecVersion = "1.17.1"
dependencies {
    implementation(platform("org.keycloak.bom:keycloak-adapter-bom:${keycloakVersion}"))
    implementation(platform("org.keycloak.bom:keycloak-misc-bom:${keycloakVersion}"))
    implementation(platform("org.keycloak.bom:keycloak-spi-bom:${keycloakVersion}"))
    compileOnlyApi("org.keycloak:keycloak-server-spi:${keycloakVersion}")
    compileOnlyApi("org.keycloak:keycloak-server-spi-private:${keycloakVersion}")
    implementation("org.keycloak:keycloak-services:${keycloakVersion}")

    constraints {
        implementation("com.google.guava:guava:${guavaVersion}")
        implementation("commons-codec:commons-codec:${commonsCodecVersion}")
    }

    testImplementation("org.junit.jupiter:junit-jupiter:${jUnitJupiterVersion}")
    testImplementation("org.mockito:mockito-junit-jupiter:${mockitoJunitVersion}")
    testImplementation("org.assertj:assertj-core:${assertJVersion}")
    testImplementation("jakarta.ws.rs:jakarta.ws.rs-api:${jakartaWsRsVersion}")
    testImplementation("org.glassfish.jersey.core:jersey-common:${jerseyVersion}")

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

tasks.withType<AbstractArchiveTask> {
    setProperty("archiveFileName", "keycloak-kubernetes-authenticator.jar")
}

sonar {
    properties {
        property("sonar.projectKey", "chr-fritz_keycloak-kubernetes-authenticator")
        property("sonar.organization", "chr-fritz")
        property("sonar.host.url", "https://sonarcloud.io")
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
                uri(
                    "https://maven.pkg.github.com/" + URLEncoder.encode(
                        System.getenv("GITHUB_ACTOR"),
                        "UTF-8"
                    ) + "/keycloak-kubernetes-authenticator"
                )
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
