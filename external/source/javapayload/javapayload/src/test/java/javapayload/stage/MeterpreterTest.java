package javapayload.stage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Random;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

import junit.framework.Assert;
import junit.framework.TestCase;

import com.metasploit.meterpreter.MemoryBufferURLConnection;
import com.metasploit.meterpreter.MeterpDummy;

public class MeterpreterTest extends TestCase {

	public void testMemoryBufferURLConnection() throws Exception {
		final String CONTENT_TYPE = "application/x-unit-test-example";
		byte[] randomData = new byte[4096];
		new Random().nextBytes(randomData);
		URL url = MemoryBufferURLConnection.createURL(randomData, CONTENT_TYPE);
		URLConnection uc = url.openConnection();
		uc.connect();
		Assert.assertEquals(CONTENT_TYPE, uc.getContentType());
		Assert.assertEquals(4096, uc.getContentLength());
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		StreamForwarder.forward(uc.getInputStream(), out);
		Assert.assertEquals(new String(randomData, "ISO-8859-1"), new String(out.toByteArray(), "ISO-8859-1"));
	}

	public void testMeterpreterStage() throws Exception {
		// build dummy Meterpreter stage
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		StreamForwarder.forward(MeterpDummy.class.getResourceAsStream(MeterpDummy.class.getSimpleName()+".class"), baos);
		String meterpDummy = new String(baos.toByteArray(), "ISO-8859-1").replace("MeterpDummy", "Meterpreter");
		baos.reset();
		JarOutputStream jos = new JarOutputStream(baos);
		jos.putNextEntry(new ZipEntry("com/metasploit/meterpreter/Meterpreter.class"));
		jos.write(meterpDummy.getBytes("ISO-8859-1"));
		jos.close();
		byte[] dummyJar = baos.toByteArray();
		
		// build payload
		baos.reset();
		dos.writeInt(dummyJar.length);
		dos.write(dummyJar);
		byte[] randomData = new byte[4096];
		new Random().nextBytes(randomData);
		dos.writeInt(randomData.length);
		dos.write(randomData);
		byte[] payload = baos.toByteArray();
		
		// test payload with output redirection enabled
		baos.reset();
		new Meterpreter().start(new DataInputStream(new ByteArrayInputStream(payload)), baos, new String[] {"Payload", "--", "Meterpreter"});
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
		byte[] roundtripData = new byte[4096];
		in.readFully(roundtripData);
		Assert.assertEquals(new String(randomData, "ISO-8859-1"), new String(roundtripData, "ISO-8859-1"));
		Assert.assertEquals(true, in.readBoolean());
		Assert.assertEquals(true, in.readBoolean());
		Assert.assertEquals(-1, in.read());
		
		// test payload with output redirection disabled
		baos.reset();
		new Meterpreter().start(new DataInputStream(new ByteArrayInputStream(payload)), baos, new String[] {"Payload", "--", "Meterpreter", "NoRedirect"});
		in = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
		roundtripData = new byte[4096];
		in.readFully(roundtripData);
		Assert.assertEquals(new String(randomData, "ISO-8859-1"), new String(roundtripData, "ISO-8859-1"));
		Assert.assertEquals(true, in.readBoolean());
		Assert.assertEquals(false, in.readBoolean());
		Assert.assertEquals(-1, in.read());	
	}
}
