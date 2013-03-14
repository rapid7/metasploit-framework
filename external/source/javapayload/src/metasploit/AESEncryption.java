package metasploit;

import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class to enable AES encryption for stagers. This is in its own class
 * because it depends on classes only present on Sun JRE 1.4+, and incorporating
 * it into the main {@link Payload} class would have made it impossible for
 * other/older JREs to load it.
 */
public class AESEncryption {
	public static Object[] wrapStreams(InputStream in, OutputStream out, String key) throws Exception {
		DataInputStream din = new DataInputStream(in);
		din.readInt(); // first class size 0 as marker in JavaPayload
		SecureRandom sr = new SecureRandom();
		byte[] outIV = new byte[16];
		sr.nextBytes(outIV);
		out.write(outIV);
		out.flush();
		byte[] inIV = new byte[16];
		din.readFully(inIV);
		byte[] keyBytes = MessageDigest.getInstance("MD5").digest(key.getBytes());
		Cipher co = Cipher.getInstance("AES/CFB8/NoPadding");
		co.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(outIV), sr);
		Cipher ci = Cipher.getInstance("AES/CFB8/NoPadding");
		ci.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(inIV), sr);
		return new Object[] {
				new CipherInputStream(din, ci),
				new CipherOutputStream(out, co),
		};
	}
}