package com.codeheadsystems.vault.storage

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Raw file I/O for the commit host (docs/android.md, Storage): a write goes to a temporary file in
 * the same directory, then `fsync`, then a rename over the target, then an `fsync` of the
 * directory, so a reader sees the old bytes or the new ones, never a mix.
 */
class AtomicFiles(
    private val dir: File,
    /** Flushes the directory entry; the app passes an `Os.fsync` of the directory descriptor. */
    private val syncDirectory: (File) -> Unit = ::syncDirectoryNio,
) {
    init {
        require(dir.isDirectory) { "not a directory: $dir" }
    }

    /** The file's bytes, or null when it does not exist. */
    fun read(name: String): ByteArray? {
        val f = file(name)
        return if (f.exists()) f.readBytes() else null
    }

    fun write(name: String, bytes: ByteArray) {
        val target = file(name)
        val temp = File(dir, ".$name.tmp")
        try {
            FileOutputStream(temp).use { out ->
                out.write(bytes)
                out.flush()
                out.fd.sync()
            }
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: IOException) {
            temp.delete()
            throw e
        }
        syncDirectory(dir)
    }

    /** Deletes the file; a missing file is not an error. */
    fun delete(name: String) {
        if (file(name).delete()) syncDirectory(dir)
    }

    private fun file(name: String): File {
        require(name.isNotEmpty() && name.none { it == '/' || it == '\u0000' } && !name.startsWith(".")) {
            "bad file name: $name"
        }
        return File(dir, name)
    }
}

/** Flushes a directory through NIO, as a JVM on Linux allows. */
fun syncDirectoryNio(dir: File) {
    FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) }
}
