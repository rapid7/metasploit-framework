package json.ext;

import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ThreadContext;
import org.jruby.util.ByteList;

/**
 * An encoder that reads from the given source and outputs its representation
 * to another ByteList. The source string is fully checked for UTF-8 validity,
 * and throws a GeneratorError if any problem is found.
 */
final class StringEncoder extends ByteListTranscoder {
    private final boolean asciiOnly;

    // Escaped characters will reuse this array, to avoid new allocations
    // or appending them byte-by-byte
    private final byte[] aux =
        new byte[] {/* First unicode character */
                    '\\', 'u', 0, 0, 0, 0,
                    /* Second unicode character (for surrogate pairs) */
                    '\\', 'u', 0, 0, 0, 0,
                    /* "\X" characters */
                    '\\', 0};
    // offsets on the array above
    private static final int ESCAPE_UNI1_OFFSET = 0;
    private static final int ESCAPE_UNI2_OFFSET = ESCAPE_UNI1_OFFSET + 6;
    private static final int ESCAPE_CHAR_OFFSET = ESCAPE_UNI2_OFFSET + 6;
    /** Array used for code point decomposition in surrogates */
    private final char[] utf16 = new char[2];

    private static final byte[] HEX =
            new byte[] {'0', '1', '2', '3', '4', '5', '6', '7',
                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    StringEncoder(ThreadContext context, boolean asciiOnly) {
        super(context);
        this.asciiOnly = asciiOnly;
    }

    void encode(ByteList src, ByteList out) {
        init(src, out);
        append('"');
        while (hasNext()) {
            handleChar(readUtf8Char());
        }
        quoteStop(pos);
        append('"');
    }

    private void handleChar(int c) {
        switch (c) {
        case '"':
        case '\\':
            escapeChar((char)c);
            break;
        case '\n':
            escapeChar('n');
            break;
        case '\r':
            escapeChar('r');
            break;
        case '\t':
            escapeChar('t');
            break;
        case '\f':
            escapeChar('f');
            break;
        case '\b':
            escapeChar('b');
            break;
        default:
            if (c >= 0x20 && c <= 0x7f ||
                    (c >= 0x80 && !asciiOnly)) {
                quoteStart();
            } else {
                quoteStop(charStart);
                escapeUtf8Char(c);
            }
        }
    }

    private void escapeChar(char c) {
        quoteStop(charStart);
        aux[ESCAPE_CHAR_OFFSET + 1] = (byte)c;
        append(aux, ESCAPE_CHAR_OFFSET, 2);
    }

    private void escapeUtf8Char(int codePoint) {
        int numChars = Character.toChars(codePoint, utf16, 0);
        escapeCodeUnit(utf16[0], ESCAPE_UNI1_OFFSET + 2);
        if (numChars > 1) escapeCodeUnit(utf16[1], ESCAPE_UNI2_OFFSET + 2);
        append(aux, ESCAPE_UNI1_OFFSET, 6 * numChars);
    }

    private void escapeCodeUnit(char c, int auxOffset) {
        for (int i = 0; i < 4; i++) {
            aux[auxOffset + i] = HEX[(c >>> (12 - 4 * i)) & 0xf];
        }
    }

    @Override
    protected RaiseException invalidUtf8() {
         return Utils.newException(context, Utils.M_GENERATOR_ERROR,
                 "source sequence is illegal/malformed utf-8");
    }
}
