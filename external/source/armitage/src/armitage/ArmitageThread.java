package armitage;

import console.Console;
import msf.*;
import java.util.*;

/** A generic class to execute several queries and return their results */
public class ArmitageThread implements Runnable {
	protected ArmitageThreadClient client;

	public ArmitageThread(ArmitageThreadClient c) {
		this.client = c;
	}

	public void start() {
		new Thread(this).start();
	}

	public void run() {
		while (true) {
			long sleepFor = client.execute();

			if (sleepFor <= 0) {
				return;
			}
			else {
				try {
					Thread.sleep(sleepFor);
				}
				catch (Exception ex) {

				}
			}
		}
	}
}
