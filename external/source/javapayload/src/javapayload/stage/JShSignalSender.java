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

import java.io.PipedOutputStream;
import java.io.PrintStream;

/**
 * For some strange reason {@link PipedOutputStream} assumes something bad[tm] happened if a thread which wrote last to it dies without closing it. Therefore, we send all the "process dead" signals to the output stream via a dedicated thread that does not end before Jsh ends...
 */
public class JShSignalSender extends Thread {
	private final PipedOutputStream signalStream;
	private boolean doSignal, doTerminate;
	private final PrintStream errorStream;

	public JShSignalSender(PipedOutputStream signalStream, PrintStream errorStream) {
		this.signalStream = signalStream;
		this.errorStream = errorStream;
		start();
	}

	public void run() {
		try {
			while (true) {
				synchronized (this) {
					while (!doSignal && !doTerminate) {
						wait();
					}
					if (doTerminate) {
						break;
					}
					doSignal = false;
				}
				signalStream.write(new byte[] { 0, '$' });
				signalStream.flush();
			}
			signalStream.close();
		} catch (final Throwable ex) {
			ex.printStackTrace(errorStream);
		}
	}

	public synchronized void signal() {
		doSignal = true;
		notifyAll();
	}

	public synchronized void terminate() {
		doTerminate = true;
		notifyAll();
	}
}
