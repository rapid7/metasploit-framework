package ysoserial;

import java.security.Permission;
import java.util.concurrent.Callable;

public class ExecBlockingSecurityManager extends SecurityManager {
	@Override
	public void checkPermission(final Permission perm) { }
	
	@Override
	public void checkPermission(final Permission perm, final Object context) { }			
	
	public void checkExec(final String cmd) {
		super.checkExec(cmd);
		// throw a special exception to ensure we can detect exec() in the test
		throw new ExecException(cmd);
	};
	
	@SuppressWarnings("serial")
	public static class ExecException extends RuntimeException {
		private final String cmd;
		public ExecException(String cmd) { this.cmd = cmd; }
		public String getCmd() { return cmd; }		
	}		
	
	public static void wrap(final Runnable runnable) throws Exception {
		wrap(new Callable<Void>(){
			public Void call() throws Exception {
				runnable.run();
				return null;
			}			
		});		
	}
	
	public static <T> T wrap(final Callable<T> callable) throws Exception {
		SecurityManager sm = System.getSecurityManager();
		System.setSecurityManager(new ExecBlockingSecurityManager());
		try {
			return callable.call();
		} finally {
			System.setSecurityManager(sm);
		}		
	}
}