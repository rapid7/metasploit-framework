/*
 * Java Payloads.
 * 
 * Copyright (c) 2010, 2011 Michael 'mihi' Schierl
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

public class StreamForwarder extends Thread {
	public static void forward(InputStream in, OutputStream out) throws IOException {
		forward(in, out, true);
	}
	
	public static void forward(InputStream in, OutputStream out, boolean closeOut) throws IOException {
		try {
			final byte[] buf = new byte[4096];
			int length;
			while ((length = in.read(buf)) != -1) {
				if (out != null) {
					out.write(buf, 0, length);
					if (in.available() == 0) {
						out.flush();
					}
				}
			}
		} finally {
			in.close();
			if (closeOut)
				out.close();
		}
	}

	private final InputStream in;
	private final OutputStream out;

	private final OutputStream stackTraceOut;
	private final boolean closeOut;

	public StreamForwarder(InputStream in, OutputStream out, OutputStream stackTraceOut) {
		this(in,out,stackTraceOut,true);
	}
	public StreamForwarder(InputStream in, OutputStream out, OutputStream stackTraceOut, boolean closeOut) {
		this.in = in;
		this.out = out;
		this.stackTraceOut = stackTraceOut;
		this.closeOut = closeOut;
	}

	public void run() {
		try {
			forward(in, out, closeOut);
		} catch (final Throwable ex) {
			if (stackTraceOut == null)
				throwWrapped(ex);
			ex.printStackTrace(new PrintStream(stackTraceOut, true));
		}
	}
	
	private static void throwWrapped(Throwable ex) {
		/* #JDK1.4 */try {
			throw new RuntimeException(ex);
		} catch (NoSuchMethodError ex2) /**/{
			throw new RuntimeException(ex.toString());
		}
	}
}
