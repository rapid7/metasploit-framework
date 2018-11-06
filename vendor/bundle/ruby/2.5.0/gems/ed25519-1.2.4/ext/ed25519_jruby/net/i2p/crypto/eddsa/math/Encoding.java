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
package net.i2p.crypto.eddsa.math;

/**
 * Common interface for all $(b-1)$-bit encodings of elements
 * of EdDSA finite fields.
 * @author str4d
 *
 */
public abstract class Encoding {
    protected Field f;

    public synchronized void setField(Field f) {
        if (this.f != null)
            throw new IllegalStateException("already set");
        this.f = f;
    }

    /**
     * Encode a FieldElement in its $(b-1)$-bit encoding.
     * @param x the FieldElement to encode
     * @return the $(b-1)$-bit encoding of this FieldElement.
     */
    public abstract byte[] encode(FieldElement x);

    /**
     * Decode a FieldElement from its $(b-1)$-bit encoding.
     * The highest bit is masked out.
     * @param in the $(b-1)$-bit encoding of a FieldElement.
     * @return the FieldElement represented by 'val'.
     */
    public abstract FieldElement decode(byte[] in);

    /**
     * From the Ed25519 paper:<br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of -x. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @param x the FieldElement to check
     * @return true if negative
     */
    public abstract boolean isNegative(FieldElement x);
}
