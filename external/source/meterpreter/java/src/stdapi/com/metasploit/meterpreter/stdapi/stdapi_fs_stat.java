package com.metasploit.meterpreter.stdapi;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_stat implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
		File file = new File(path);
		if (!file.exists())
			file = Loader.expand(path);
		if (!file.exists())
			throw new IOException("File/directory does not exist: " + path);
		response.add(TLVType.TLV_TYPE_STAT_BUF, stat(file));
		return ERROR_SUCCESS;
	}

	public byte[] stat(File file) throws IOException {
		ByteArrayOutputStream statbuf = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(statbuf);
		dos.writeInt(le(0)); // dev
		dos.writeShort(short_le(0)); // ino
		int mode = (file.canRead() ? 0444 : 0) | (file.canWrite() ? 0222 : 0) | (canExecute(file) ? 0110 : 0) | (file.isHidden() ? 1 : 0) | (file.isDirectory() ? 040000 : 0) | (file.isFile() ? 0100000 : 0);
		dos.writeShort(short_le(mode)); // mode
		dos.writeShort(short_le(1)); // nlink
		dos.writeShort(short_le(65535)); // uid
		dos.writeShort(short_le(65535)); // gid
		dos.writeShort(short_le(0)); // padding
		dos.writeInt(le(0)); // rdev
		dos.writeInt(le((int) file.length())); // size
		int mtime = (int) (file.lastModified() / 1000);
		dos.writeInt(le(mtime)); // atime
		dos.writeInt(le(mtime)); // mtime
		dos.writeInt(le(mtime)); // ctime
		dos.writeInt(le(1024)); // blksize
		dos.writeInt(le((int) ((file.length() + 1023) / 1024))); // blocks
		return statbuf.toByteArray();
	}

	/**
	 * Check whether a file can be executed.
	 */
	protected boolean canExecute(File file) {
		return false;
	}

	/**
	 * Convert an integer to little endian.
	 */
	private static int le(int value) {
		return ((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value & 0xff0000) >> 8) | (int) ((value & 0xff000000L) >> 24);
	}

	/**
	 * Convert a short to little endian.
	 */
	private static int short_le(int value) {
		return ((value & 0xff) << 8) | ((value & 0xff00) >> 8);
	}
}
