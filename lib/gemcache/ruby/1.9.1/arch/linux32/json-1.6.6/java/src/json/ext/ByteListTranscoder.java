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
 * A class specialized in transcoding a certain String format into another,
 * using UTF-8 ByteLists as both input and output.
 */
abstract class ByteListTranscoder {
    protected final ThreadContext context;

    protected ByteList src;
    protected int srcEnd;
    /** Position where the last read character started */
    protected int charStart;
    /** Position of the next character to read */
    protected int pos;

    private ByteList out;
    /**
     * When a character that can be copied straight into the output is found,
     * its index is stored on this variable, and copying is delayed until
     * the sequence of characters that can be copied ends.
     *
     * <p>The variable stores -1 when not in a plain sequence.
     */
    private int quoteStart = -1;

    protected ByteListTranscoder(ThreadContext context) {
        this.context = context;
    }

    protected void init(ByteList src, ByteList out) {
        this.init(src, 0, src.length(), out);
    }

    protected void init(ByteList src, int start, int end, ByteList out) {
        this.src = src;
        this.pos = start;
        this.charStart = start;
        this.srcEnd = end;
        this.out = out;
    }

    /**
     * Returns whether there are any characters left to be read.
     */
    protected boolean hasNext() {
        return pos < srcEnd;
    }

    /**
     * Returns the next character in the buffer.
     */
    private char next() {
        return src.charAt(pos++);
    }

    /**
     * Reads an UTF-8 character from the input and returns its code point,
     * while advancing the input position.
     *
     * <p>Raises an {@link #invalidUtf8()} exception if an invalid byte
     * is found.
     */
    protected int readUtf8Char() {
        charStart = pos;
        char head = next();
        if (head <= 0x7f) { // 0b0xxxxxxx (ASCII)
            return head;
        }
        if (head <= 0xbf) { // 0b10xxxxxx
            throw invalidUtf8(); // tail byte with no head
        }
        if (head <= 0xdf) { // 0b110xxxxx
            ensureMin(1);
            int cp = ((head  & 0x1f) << 6)
                     | nextPart();
            if (cp < 0x0080) throw invalidUtf8();
            return cp;
        }
        if (head <= 0xef) { // 0b1110xxxx
            ensureMin(2);
            int cp = ((head & 0x0f) << 12)
                     | (nextPart()  << 6)
                     | nextPart();
            if (cp < 0x0800) throw invalidUtf8();
            return cp;
        }
        if (head <= 0xf7) { // 0b11110xxx
            ensureMin(3);
            int cp = ((head & 0x07) << 18)
                     | (nextPart()  << 12)
                     | (nextPart()  << 6)
                     | nextPart();
            if (!Character.isValidCodePoint(cp)) throw invalidUtf8();
            return cp;
        }
        // 0b11111xxx?
        throw invalidUtf8();
    }

    /**
     * Throws a GeneratorError if the input list doesn't have at least this
     * many bytes left.
     */
    protected void ensureMin(int n) {
        if (pos + n > srcEnd) throw incompleteUtf8();
    }

    /**
     * Reads the next byte of a multi-byte UTF-8 character and returns its
     * contents (lower 6 bits).
     *
     * <p>Throws a GeneratorError if the byte is not a valid tail.
     */
    private int nextPart() {
        char c = next();
        // tail bytes must be 0b10xxxxxx
        if ((c & 0xc0) != 0x80) throw invalidUtf8();
        return c & 0x3f;
    }


    protected void quoteStart() {
        if (quoteStart == -1) quoteStart = charStart;
    }

    /**
     * When in a sequence of characters that can be copied directly,
     * interrupts the sequence and copies it to the output buffer.
     *
     * @param endPos The offset until which the direct character quoting should
     *               occur. You may pass {@link #pos} to quote until the most
     *               recently read character, or {@link #charStart} to quote
     *               until the character before it.
     */
    protected void quoteStop(int endPos) {
        if (quoteStart != -1) {
            out.append(src, quoteStart, endPos - quoteStart);
            quoteStart = -1;
        }
    }

    protected void append(int b) {
        out.append(b);
    }

    protected void append(byte[] origin, int start, int length) {
        out.append(origin, start, length);
    }


    protected abstract RaiseException invalidUtf8();

    protected RaiseException incompleteUtf8() {
        return invalidUtf8();
    }
}
