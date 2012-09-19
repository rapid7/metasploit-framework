/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby and GPLv2 licenses; see COPYING and GPL files
 * for details.
 */
package json.ext;

import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ThreadContext;
import org.jruby.util.ByteList;

/**
 * A decoder that reads a JSON-encoded string from the given sources and
 * returns its decoded form on a new ByteList. Escaped Unicode characters
 * are encoded as UTF-8.
 */
final class StringDecoder extends ByteListTranscoder {
    /**
     * Stores the offset of the high surrogate when reading a surrogate pair,
     * or -1 when not.
     */
    private int surrogatePairStart = -1;

    // Array used for writing multi-byte characters into the buffer at once
    private final byte[] aux = new byte[4];

    StringDecoder(ThreadContext context) {
        super(context);
    }

    ByteList decode(ByteList src, int start, int end) {
        ByteList out = new ByteList(end - start);
        out.setEncoding(src.getEncoding());
        init(src, start, end, out);
        while (hasNext()) {
            handleChar(readUtf8Char());
        }
        quoteStop(pos);
        return out;
    }

    private void handleChar(int c) {
        if (c == '\\') {
            quoteStop(charStart);
            handleEscapeSequence();
        } else {
            quoteStart();
        }
    }

    private void handleEscapeSequence() {
        ensureMin(1);
        switch (readUtf8Char()) {
        case 'b':
            append('\b');
            break;
        case 'f':
            append('\f');
            break;
        case 'n':
            append('\n');
            break;
        case 'r':
            append('\r');
            break;
        case 't':
            append('\t');
            break;
        case 'u':
            ensureMin(4);
            int cp = readHex();
            if (Character.isHighSurrogate((char)cp)) {
                handleLowSurrogate((char)cp);
            } else if (Character.isLowSurrogate((char)cp)) {
                // low surrogate with no high surrogate
                throw invalidUtf8();
            } else {
                writeUtf8Char(cp);
            }
            break;
        default: // '\\', '"', '/'...
            quoteStart();
        }
    }

    private void handleLowSurrogate(char highSurrogate) {
        surrogatePairStart = charStart;
        ensureMin(1);
        int lowSurrogate = readUtf8Char();

        if (lowSurrogate == '\\') {
            ensureMin(5);
            if (readUtf8Char() != 'u') throw invalidUtf8();
            lowSurrogate = readHex();
        }

        if (Character.isLowSurrogate((char)lowSurrogate)) {
            writeUtf8Char(Character.toCodePoint(highSurrogate,
                                                (char)lowSurrogate));
            surrogatePairStart = -1;
        } else {
            throw invalidUtf8();
        }
    }

    private void writeUtf8Char(int codePoint) {
        if (codePoint < 0x80) {
            append(codePoint);
        } else if (codePoint < 0x800) {
            aux[0] = (byte)(0xc0 | (codePoint >>> 6));
            aux[1] = tailByte(codePoint & 0x3f);
            append(aux, 0, 2);
        } else if (codePoint < 0x10000) {
            aux[0] = (byte)(0xe0 | (codePoint >>> 12));
            aux[1] = tailByte(codePoint >>> 6);
            aux[2] = tailByte(codePoint);
            append(aux, 0, 3);
        } else {
            aux[0] = (byte)(0xf0 | codePoint >>> 18);
            aux[1] = tailByte(codePoint >>> 12);
            aux[2] = tailByte(codePoint >>> 6);
            aux[3] = tailByte(codePoint);
            append(aux, 0, 4);
        }
    }

    private byte tailByte(int value) {
        return (byte)(0x80 | (value & 0x3f));
    }

    /**
     * Reads a 4-digit unsigned hexadecimal number from the source.
     */
    private int readHex() {
        int numberStart = pos;
        int result = 0;
        int length = 4;
        for (int i = 0; i < length; i++) {
            int digit = readUtf8Char();
            int digitValue;
            if (digit >= '0' && digit <= '9') {
                digitValue = digit - '0';
            } else if (digit >= 'a' && digit <= 'f') {
                digitValue = 10 + digit - 'a';
            } else if (digit >= 'A' && digit <= 'F') {
                digitValue = 10 + digit - 'A';
            } else {
                throw new NumberFormatException("Invalid base 16 number "
                        + src.subSequence(numberStart, numberStart + length));
            }
            result = result * 16 + digitValue;
        }
        return result;
    }

    @Override
    protected RaiseException invalidUtf8() {
        ByteList message = new ByteList(
                ByteList.plain("partial character in source, " +
                               "but hit end near "));
        int start = surrogatePairStart != -1 ? surrogatePairStart : charStart;
        message.append(src, start, srcEnd - start);
        return Utils.newException(context, Utils.M_PARSER_ERROR,
                                  context.getRuntime().newString(message));
    }
}
