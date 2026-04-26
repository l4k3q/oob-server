plugins {
    java
    id("org.springframework.boot") version "3.2.5"
    id("io.spring.dependency-management") version "1.1.5"
}

group = "com.oobx"
version = "0.1.0"

java {
    toolchain { languageVersion = JavaLanguageVersion.of(11) }
}

repositories {
    mavenCentral()
    // For javassist & asm
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-validation")

    // Bytecode generation
    implementation("org.javassist:javassist:3.30.2-GA")
    implementation("org.ow2.asm:asm:9.7")
    implementation("org.ow2.asm:asm-util:9.7")
    implementation("net.bytebuddy:byte-buddy:1.14.15")

    // LDAP / marshalsec-like helpers
    implementation("org.apache.directory.api:api-all:2.1.5")

    // Base64, commons-io
    implementation("commons-io:commons-io:2.15.1")
    implementation("org.apache.commons:commons-lang3:3.14.0")

    // ysoserial shaded (bring your own jar or build from source)
    // Uncomment if you drop ysoserial.jar into libs/
    // implementation(files("libs/ysoserial-all.jar"))

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.oobx.App"
    }
}

tasks.bootJar {
    archiveFileName = "bytecode-service.jar"
}
