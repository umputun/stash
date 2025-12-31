plugins {
    `java-library`
    `maven-publish`
}

group = "com.github.umputun"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    // json parsing
    implementation("com.google.code.gson:gson:2.11.0")

    // argon2id key derivation
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")

    // testing
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.assertj:assertj-core:3.27.3")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

publishing {
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/umputun/stash")
            credentials {
                username = System.getenv("GITHUB_ACTOR") ?: ""
                password = System.getenv("GITHUB_TOKEN") ?: ""
            }
        }
    }
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            artifactId = "stash-client"

            pom {
                name.set("Stash Client")
                description.set("Java client library for Stash - a simple key-value configuration service")
                url.set("https://github.com/umputun/stash")

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                developers {
                    developer {
                        id.set("umputun")
                        name.set("Umputun")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/umputun/stash.git")
                    developerConnection.set("scm:git:ssh://github.com/umputun/stash.git")
                    url.set("https://github.com/umputun/stash")
                }
            }
        }
    }
}

tasks.withType<Javadoc> {
    options {
        (this as StandardJavadocDocletOptions).apply {
            addStringOption("Xdoclint:none", "-quiet")
        }
    }
}
