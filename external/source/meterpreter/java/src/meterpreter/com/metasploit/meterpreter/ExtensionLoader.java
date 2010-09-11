package com.metasploit.meterpreter;

/**
 * A loader class for an extension. This loader must be referenced in the jar manifest's Extension-Loader entry.
 * 
 * @author mihi
 */
public interface ExtensionLoader {

	public static final int V1_2 = 12;
	public static final int V1_3 = 13;
	public static final int V1_4 = 14;
	public static final int V1_5 = 15;
	public static final int V1_6 = 16;

	/**
	 * Load this extension.
	 * 
	 * @param commandManager
	 *            command manager to load commands into.
	 */
	public void load(CommandManager commandManager) throws Exception;
}
