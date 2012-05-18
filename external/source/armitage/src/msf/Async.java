package msf;

import java.io.*;

public interface Async {
	public void execute_async(String methodName);
	public void execute_async(String methodName, Object[] args);
}
