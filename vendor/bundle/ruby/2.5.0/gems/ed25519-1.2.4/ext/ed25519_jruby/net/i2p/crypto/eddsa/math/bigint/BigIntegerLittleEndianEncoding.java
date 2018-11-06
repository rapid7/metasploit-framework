/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa.math.bigint;

import java.io.Serializable;
import java.math.BigInteger;

import net.i2p.crypto.eddsa.math.Encoding;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;

public class BigIntegerLittleEndianEncoding extends Encoding implements Serializable {
    private static final long serialVersionUID = 3984579843759837L;
    /**
     * Mask where only the first b-1 bits are set.
     */
    private BigInteger mask;

    @Override
    public synchronized void setField(Field f) {
        super.setField(f);
        mask = BigInteger.ONE.shiftLeft(f.getb()-1).subtract(BigInteger.ONE);
    }

    public byte[] encode(FieldElement x) {
        return encode(((BigIntegerFieldElement)x).bi.and(mask));
    }

    /**
     *  Convert $x$ to little endian.
     *  Constant time.
     *
     *  @param x the BigInteger value to encode
     *  @return array of length $b/8$
     *  @throws IllegalStateException if field not set
     */
    public byte[] encode(BigInteger x) {
        if (f == null)
            throw new IllegalStateException("field not set");
        byte[] in = x.toByteArray();
        byte[] out = new byte[f.getb()/8];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        for (int i = in.length; i < out.length; i++) {
            out[i] = 0;
        }
        return out;
    }

    /**
     *  Decode a FieldElement from its $(b-1)$-bit encoding.
     *  The highest bit is masked out.
     *
     *  @param in the $(b-1)$-bit encoding of a FieldElement.
     *  @return the FieldElement represented by 'val'.
     *  @throws IllegalStateException if field not set
     *  @throws IllegalArgumentException if encoding is invalid
     */
    public FieldElement decode(byte[] in) {
        if (f == null)
            throw new IllegalStateException("field not set");
        if (in.length != f.getb()/8)
            throw new IllegalArgumentException("Not a valid encoding");
        return new BigIntegerFieldElement(f, toBigInteger(in).and(mask));
    }

    /**
     *  Convert in to big endian
     *
     *  @param in the $(b-1)$-bit encoding of a FieldElement.
     *  @return the decoded value as a BigInteger
     */
    public BigInteger toBigInteger(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        return new BigInteger(1, out);
    }

    /**
     * From the Ed25519 paper:<br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of $-x$. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @return true if negative
     */
    public boolean isNegative(FieldElement x) {
        return ((BigIntegerFieldElement)x).bi.testBit(0);
    }
}
