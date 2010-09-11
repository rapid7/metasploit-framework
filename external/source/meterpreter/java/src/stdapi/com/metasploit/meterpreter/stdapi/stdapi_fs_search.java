package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_search implements Command {

	private static final int TLV_TYPE_FILE_SIZE = TLVPacket.TLV_META_TYPE_UINT | 1204;

	private static final int TLV_TYPE_SEARCH_RECURSE = TLVPacket.TLV_META_TYPE_BOOL | 1230;
	private static final int TLV_TYPE_SEARCH_GLOB = TLVPacket.TLV_META_TYPE_STRING | 1231;
	private static final int TLV_TYPE_SEARCH_ROOT = TLVPacket.TLV_META_TYPE_STRING | 1232;
	private static final int TLV_TYPE_SEARCH_RESULTS = TLVPacket.TLV_META_TYPE_GROUP | 1233;

	/**
	 * Simple glob implementation.
	 */
	private static boolean matches(String text, String glob) {
		String rest = null;
		int pos = glob.indexOf('*');
		if (pos != -1) {
			rest = glob.substring(pos + 1);
			glob = glob.substring(0, pos);
		}

		if (glob.length() > text.length())
			return false;

		// handle the part up to the first *
		for (int i = 0; i < glob.length(); i++)
			if (glob.charAt(i) != '?' 
					&& !glob.substring(i, i + 1).equalsIgnoreCase(text.substring(i, i + 1)))
				return false;

		// recurse for the part after the first *, if any
		if (rest == null) {
			return glob.length() == text.length();
		} else {
			for (int i = glob.length(); i <= text.length(); i++) {
				if (matches(text.substring(i), rest))
					return true;
			}
			return false;
		}
	}

	private List findFiles(String path, String mask, boolean recurse) {
		try {
			File pathfile = new File(Loader.cwd, path);
			if (!pathfile.exists() || !pathfile.isDirectory()) {
				pathfile = new File(path);
				if (!pathfile.exists() || !pathfile.isDirectory()) {
					throw new IOException("Path not found: " + path);
				}
			}
			path = pathfile.getCanonicalPath();
			File[] lst = new File(path).listFiles();
			List glob = new ArrayList();
			if (lst == null)
				return glob;
			for (int i = 0; i < lst.length; i++) {
				File file = lst[i];
				if (recurse && file.isDirectory()
						// don't follow links to avoid infinite recursion
						&& file.getCanonicalPath().equals(file.getAbsolutePath())) {
					glob.addAll(findFiles(file.getAbsolutePath(), mask, true));
				}
				// Match file mask
				if (matches(file.getName(), mask)) {
					glob.add(path + "/" + file.getName());
				}
			}
			Collections.sort(glob);
			return glob;
		} catch (IOException ex) {
			return Collections.EMPTY_LIST;
		}
	}

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String root = request.getStringValue(TLV_TYPE_SEARCH_ROOT, ".");
		String glob = request.getStringValue(TLV_TYPE_SEARCH_GLOB);
		boolean recurse = request.getBooleanValue(TLV_TYPE_SEARCH_RECURSE);
		List files = findFiles(root, glob, recurse);
		for (int i = 0; i < files.size(); i++) {
			File f = new File((String) files.get(i));
			TLVPacket file_tlvs = new TLVPacket();
			file_tlvs.add(TLVType.TLV_TYPE_FILE_PATH, f.getParentFile().getPath());
			file_tlvs.add(TLVType.TLV_TYPE_FILE_NAME, f.getName());
			file_tlvs.add(TLV_TYPE_FILE_SIZE, (int) f.length());
			response.addOverflow(TLV_TYPE_SEARCH_RESULTS, file_tlvs);
		}
		return ERROR_SUCCESS;
	}
}
