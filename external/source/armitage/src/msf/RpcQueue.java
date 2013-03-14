package msf;

import console.*;

import java.util.*;
import java.awt.*;
import java.awt.event.*;

import msf.*;
import java.math.*;
import java.security.*;

/* A pretty quick and dirty queue for executing RPC commands in turn and discarding their output. This
   has to be 100x better than creating a thread for every async thing I want to have happen via an RPC
   call */
public class RpcQueue implements Runnable {
	protected RpcConnection connection;
	protected LinkedList    requests  = new LinkedList();

	private static class Request {
		public String   method;
		public Object[] args;
	}

	public RpcQueue(RpcConnection connection) {
		this.connection = connection;
		new Thread(this).start();
	}

	protected void processRequest(Request r) {
		try {
			connection.execute(r.method, r.args);
		}
		catch (Exception ex) {
			System.err.println("-------------------");
			System.err.println("Method: " + r.method);
			for (int x = 0; x < r.args.length; x++) {
				System.err.println("\t" + x + ": " + r.args[x]);
			}
			ex.printStackTrace();
		}
	}

	public void execute(String method, Object[] args) {
		synchronized (this) {
			Request temp = new Request();
			temp.method = method;
			temp.args   = args;
			requests.add(temp);
		}
	}

	protected Request grabRequest() {
		synchronized (this) {
			return (Request)requests.pollFirst();
		}
	}

	/* keep grabbing requests */
	public void run() {
		try {
			while (true) {
				Request next = grabRequest();
				if (next != null) {
					processRequest(next);
					Thread.sleep(50);
				}
				else {
					Thread.sleep(200);
				}
			}
		}
		catch (Exception ex) {
			ex.printStackTrace();
			return;
		}
	}
}
