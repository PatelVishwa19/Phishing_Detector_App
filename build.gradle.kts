plugins {
    id("com.android.application") version "8.1.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.0" apply false
}
buildscript {
    dependencies {
        classpath("com.android.tools.build:gradle:${libs.versions.agp.get()}")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.22")
    }
    configurations.all {
        resolutionStrategy {
            force("androidx.appcompat:appcompat:1.7.0")  // Adjust version if needed
            force("com.google.android.material:material:1.12.0")
            force("androidx.constraintlayout:constraintlayout:2.2.0")
        }
    }

}

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
}