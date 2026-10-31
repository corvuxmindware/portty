import java.io.File
import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

open class BuildTask : DefaultTask() {
    @Input
    var rootDirRel: String? = null
    @Input
    var target: String? = null
    @Input
    var release: Boolean? = null

    @TaskAction
    fun assemble() {
        buildLibrary()
        if (release == true) {
            assertNoBuildMachinePaths()
        }
    }

    private fun buildLibrary() {
        val executable = """pnpm""";
        try {
            runTauriCli(executable)
        } catch (e: Exception) {
            if (Os.isFamily(Os.FAMILY_WINDOWS)) {
                // Try different Windows-specific extensions
                val fallbacks = listOf(
                    "$executable.exe",
                    "$executable.cmd",
                    "$executable.bat",
                )
                
                var lastException: Exception = e
                for (fallback in fallbacks) {
                    try {
                        runTauriCli(fallback)
                        return
                    } catch (fallbackException: Exception) {
                        lastException = fallbackException
                    }
                }
                throw lastException
            } else {
                throw e;
            }
        }
    }

    fun runTauriCli(executable: String) {
        val rootDirRel = rootDirRel ?: throw GradleException("rootDirRel cannot be null")
        val target = target ?: throw GradleException("target cannot be null")
        val release = release ?: throw GradleException("release cannot be null")
        val args = listOf("tauri", "android", "android-studio-script");

        project.exec {
            workingDir(File(project.projectDir, rootDirRel))
            executable(executable)
            args(args)
            if (project.logger.isEnabled(LogLevel.DEBUG)) {
                args("-vv")
            } else if (project.logger.isEnabled(LogLevel.INFO)) {
                args("-v")
            }
            if (release) {
                args("--release")
            }
            args(listOf("--target", target))
        }.assertNormalExitValue()
    }

    // A release library must not name the machine that built it: its home
    // folder (C:\Users\<name>\.cargo\registry\...) or its checkout. Panic
    // locations and file!() embed both unless app/scripts/tauri.mjs remaps
    // them, and `npx tauri` or `cargo tauri` would skip that script.
    private fun assertNoBuildMachinePaths() {
        val rootDirRel = rootDirRel ?: return
        val abi = mapOf(
            "aarch64" to "arm64-v8a",
            "armv7" to "armeabi-v7a",
            "i686" to "x86",
            "x86_64" to "x86_64",
        )[target] ?: return
        val folders = listOfNotNull(
            File(System.getProperty("user.home")),
            System.getenv("CARGO_HOME")?.takeIf { it.isNotEmpty() }?.let { File(it) },
            File(project.projectDir, rootDirRel).resolve("../.."),
        )
            .flatMap { listOf(it.absoluteFile.normalize().path, it.canonicalPath) }
            .flatMap { listOf("$it\\", "$it/", it.replace('\\', '/') + "/") }
            .map { it.lowercase() }
            .distinct()
        // Tauri leaves the library here (a link into the cargo target dir).
        val libraries = File(project.projectDir, "src/main/jniLibs/$abi")
            .listFiles { file -> file.name.endsWith(".so") }
            .orEmpty()
        for (library in libraries) {
            val text = String(library.readBytes(), Charsets.ISO_8859_1).lowercase()
            val leaked = folders.filter { text.contains(it) }
            if (leaked.isNotEmpty()) {
                throw GradleException(
                    "${library.name} still names build-machine folders $leaked. " +
                        "Build Android releases with `pnpm tauri android build`; " +
                        "app/scripts/tauri.mjs adds the --remap-path-prefix flags."
                )
            }
        }
    }
}
