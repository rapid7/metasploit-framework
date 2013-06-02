package javapayload.stage;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;

public class DummyStage implements Stage {
	public void start(DataInputStream in, OutputStream rawOut, String[] parameters) throws Exception {
		byte[] buffer = new byte[in.readInt()];
		in.readFully(buffer);
		DataOutputStream out = new DataOutputStream(rawOut);
		out.write(buffer);
		out.writeInt(parameters.length);
		for (int i = 0; i < parameters.length; i++) {
			out.writeUTF(parameters[i]);
		}
		in.close();
		out.close();
	}
}
