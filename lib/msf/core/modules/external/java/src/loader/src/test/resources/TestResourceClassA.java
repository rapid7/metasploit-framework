import java.io.File;
import java.io.FileWriter;

public class TestResourceClassA {
    public static void main(String[] args) throws Exception {
        File testTempFile = new File("_temp_test_file_for_MsfPluginLoaderTest.log");
        if (!testTempFile.exists()) {
            testTempFile.createNewFile();
        }
        try (
                FileWriter fileWriter = new FileWriter(testTempFile);
        ) {
            for (int i = 0; i < 10; i++) {
                System.out.println(i);
                fileWriter.write("" + i);
            }
        }
    }
}
