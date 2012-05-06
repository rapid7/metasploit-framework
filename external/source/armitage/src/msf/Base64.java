package msf;

import java.io.*;

/**
 * Simple Base64 encoding/decoding. Very loosely based on Apache Base64 class.
 *
 * @author scriptjunkie
 *
 * Taken from the MSF Java GUI Framework.
 */
public class Base64 {
	private static final char intToBase64[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
		'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
		'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
		'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', '+', '/'
	};
	private static final byte base64ToInt[] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, 62, -1, -1, -1, 63, 52, 53,
		54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
		-1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
		5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
		29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
		49, 50, 51
	};

	public static String encode(String source) {
		try {
			return encode(source.getBytes("UTF-8"));
		} 
		catch (Exception ex) {
			return encode(source.getBytes());
		}
	}

	/** Converts a byte array to a bae64-encoded String. */
	public static String encode(byte source[]) {
		int offset = 0;
		int num = 0;
		int numBytes = 0;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < source.length; i++) {
			int b = source[offset++];
			if (b < 0)
				b += 256;
			num = (num << 8) + b;
			if (++numBytes != 3)
				continue;
			sb.append(intToBase64[num >> 18]);
			sb.append(intToBase64[num >> 12 & 0x3f]);
			sb.append(intToBase64[num >> 6 & 0x3f]);
			sb.append(intToBase64[num & 0x3f]);
			num = 0;
			numBytes = 0;
		}
		if (numBytes > 0) {
			if (numBytes == 1) {
				sb.append(intToBase64[num >> 2]);
				sb.append(intToBase64[num << 4 & 0x3f]);
				sb.append("==");
			} else {
				sb.append(intToBase64[num >> 10]);
				sb.append(intToBase64[num >> 4 & 0x3f]);
				sb.append(intToBase64[num << 2 & 0x3f]);
				sb.append('=');
			}
		}
		return sb.toString();
	}
	/** Decodes a Base64-encoded String to a byte array. */
	public static byte[] decode(String source) {
		int num=0;
		int numBytes=0;
		int eofBytes = 0;
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		for (int i = 0; i < source.length(); i++) {
			char c = source.charAt(i);
			if (Character.isWhitespace(c))
				continue;
			if (c == '=') {
				eofBytes++;
				num = num << 6;
				switch (++numBytes) {
					case 1:
					case 2: 
						throw new RuntimeException("Unexpected end of stream character (=)");
					case 3:
						break;
					case 4: 
						bout.write((byte) (num >> 16));
						if (eofBytes == 1)
							bout.write((byte) (num >> 8));
						break;
					case 5:
						throw new RuntimeException("Trailing garbage detected");
					default:
						throw new IllegalStateException("Invalid value for numBytes");
				}
				continue;
			}
			if (eofBytes > 0)
				throw new RuntimeException("Base64 characters after end of stream character (=) detected.");
			if (c >= 0 && c < Base64.base64ToInt.length) {
				int result = Base64.base64ToInt[c];
				if (result >= 0) {
					num = (num << 6) + result;
					if (++numBytes != 4)
						continue;
					bout.write((byte) (num >> 16));
					bout.write((byte) (num >> 8 & 0xff));
					bout.write((byte) (num & 0xff));
					num = 0;
					numBytes = 0;
					continue;
				}
			}
			if (!Character.isWhitespace(c))
				throw new RuntimeException("Invalid Base64 character: " + (int) c);
		}
		return bout.toByteArray();
	}
}
