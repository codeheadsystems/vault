package com.codeheadsystems.vault.storage

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class AtomicFilesTest {
    private val dir: File = Files.createTempDirectory("atomic").toFile().apply { deleteOnExit() }
    private val synced = mutableListOf<File>()
    private val files = AtomicFiles(dir) { synced += it }

    @Test
    fun writeReplacesAndSyncsTheDirectory() {
        files.write("local.json", byteArrayOf(1, 2))
        files.write("local.json", byteArrayOf(3))
        assertArrayEquals(byteArrayOf(3), files.read("local.json"))
        assertEquals(listOf(dir, dir), synced)
        // No temporary file is left behind.
        assertEquals(listOf("local.json"), dir.list()!!.toList())
    }

    @Test
    fun aMissingFileReadsAsNull() {
        assertNull(files.read("absent"))
        files.delete("absent")
        assertEquals(emptyList<File>(), synced)
    }

    @Test
    fun deleteRemovesAndSyncs() {
        files.write("device-id", byteArrayOf(9))
        files.delete("device-id")
        assertNull(files.read("device-id"))
        assertEquals(2, synced.size)
    }

    @Test
    fun namesCannotLeaveTheDirectoryOrHideAsTemporaryFiles() {
        for (bad in listOf("", "../x", "a/b", ".local.json.tmp", "a\u0000b")) {
            assertThrows(bad, IllegalArgumentException::class.java) { files.write(bad, byteArrayOf()) }
        }
    }

    @Test
    fun theNioDirectorySyncWorksOnLinux() {
        syncDirectoryNio(dir)
    }
}
