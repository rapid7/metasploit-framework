package msf;

import java.io.*;

public class RpcAsync implements RpcConnection, Async {
	protected RpcQueue queue;
	protected RpcConnection connection;

	public RpcAsync(RpcConnection connection) {
		this.connection = connection;
	}

	public void execute_async(String methodName) {
		execute_async(methodName, new Object[]{});
	}

	public void execute_async(String methodName, Object[] args) {
		if (queue == null) {
			queue = new RpcQueue(connection);
		}
		queue.execute(methodName, args);
	}

	public Object execute(String methodName) throws IOException {
		return connection.execute(methodName);
	}

	public Object execute(String methodName, Object[] params) throws IOException {
		return connection.execute(methodName, params);
	}
}
