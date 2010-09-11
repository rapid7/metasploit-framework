package com.metasploit.meterpreter;

import java.io.IOException;
import java.io.InputStream;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;

/**
 * A channel for a started {@link Process}.
 * 
 * @author mihi
 */
public class ProcessChannel extends Channel {

	private final Process process;
	private final InputStream err;

	/**
	 * Create a new process channel.
	 * 
	 * @param meterpreter
	 *            The meterpreter this channel should be assigned to.
	 * @param process
	 *            Process of the channel
	 */
	public ProcessChannel(Meterpreter meterpreter, Process process) {
		super(meterpreter, process.getInputStream(), process.getOutputStream());
		this.process = process;
		this.err = process.getErrorStream();
		new InteractThread(err).start();
	}

	public void close() throws IOException {
		process.destroy();
		err.close();
		super.close();
	}
}
