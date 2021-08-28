
plugins {
  kotlin("jvm") version "1.5.21"
  id("com.github.johnrengelman.shadow") version "7.0.0"
  application
}

group = "com.cplier"
version = "1.0-SNAPSHOT"

val tornadofx_version: String by rootProject
val netty_version: String by project
val kotlin_version: String by project
val kotlinx_version: String by project
val bounctycastle_version: String by project
val log4j2_version: String by project
val junit5_version: String by project


repositories {
  mavenCentral()
}

application {
  mainClassName = "com.cplier.MainKt"
}

dependencies {
  implementation(kotlin("stdlib-jdk8"))
  implementation(kotlin("reflect"))
  implementation("no.tornado:tornadofx:$tornadofx_version")
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinx_version")
  implementation("io.netty:netty-all:$netty_version")
  implementation("org.bouncycastle:bctls-jdk15on:$bounctycastle_version")
  implementation("org.bouncycastle:bcpkix-jdk15on:$bounctycastle_version")
  implementation("org.apache.logging.log4j:log4j-api:$log4j2_version")
  implementation("org.apache.logging.log4j:log4j-core:$log4j2_version")
  implementation("org.apache.logging.log4j:log4j-slf4j-impl:$log4j2_version")
  testImplementation(kotlin("test"))
  testImplementation("org.junit.jupiter:junit-jupiter:$junit5_version")
}



tasks {
  compileKotlin {
    kotlinOptions.jvmTarget = "1.8"
  }
  compileTestKotlin {
    kotlinOptions.jvmTarget = "1.8"
  }
  test {
    useJUnitPlatform()
  }
}


