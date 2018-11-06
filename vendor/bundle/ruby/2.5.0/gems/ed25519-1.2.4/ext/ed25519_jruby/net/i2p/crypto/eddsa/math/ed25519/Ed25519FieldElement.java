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
package net.i2p.crypto.eddsa.math.ed25519;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.*;

import java.util.Arrays;

/**
 * Class to represent a field element of the finite field $p = 2^{255} - 19$ elements.
 * <p>
 * An element $t$, entries $t[0] \dots t[9]$, represents the integer
 * $t[0]+2^{26} t[1]+2^{51} t[2]+2^{77} t[3]+2^{102} t[4]+\dots+2^{230} t[9]$.
 * Bounds on each $t[i]$ vary depending on context.
 * <p>
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
public class Ed25519FieldElement extends FieldElement {
    /**
     * Variable is package private for encoding.
     */
    final int[] t;

    /**
     * Creates a field element.
     *
     * @param f The underlying field, must be the finite field with $p = 2^{255} - 19$ elements
     * @param t The $2^{25.5}$ bit representation of the field element.
     */
    public Ed25519FieldElement(Field f, int[] t) {
        super(f);
        if (t.length != 10)
            throw new IllegalArgumentException("Invalid radix-2^51 representation");
        this.t = t;
    }

    private static final byte[] ZERO = new byte[32];

    /**
     * Gets a value indicating whether or not the field element is non-zero.
     *
     * @return 1 if it is non-zero, 0 otherwise.
     */
    public boolean isNonZero() {
        final byte[] s = toByteArray();
        return Utils.equal(s, ZERO) == 0;
    }

    /**
     * $h = f + g$
     * <p>
     * TODO-CR BR: $h$ is allocated via new, probably not a good idea. Do we need the copying into temp variables if we do that?
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <li>$|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     * </ul>
     *
     * @param val The field element to add.
     * @return The field element this + val.
     */
    public FieldElement add(FieldElement val) {
        int[] g = ((Ed25519FieldElement)val).t;
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = t[i] + g[i];
        }
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = f - g$
     * <p>
     * Can overlap $h$ with $f$ or $g$.
     * <p>
     * TODO-CR BR: See above.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <li>$|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     * </ul>
     *
     * @param val The field element to subtract.
     * @return The field element this - val.
     **/
    public FieldElement subtract(FieldElement val) {
        int[] g = ((Ed25519FieldElement)val).t;
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = t[i] - g[i];
        }
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = -f$
     * <p>
     * TODO-CR BR: see above.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul>
     *
     * @return The field element (-1) * this.
     */
    public FieldElement negate() {
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = - t[i];
        }
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = f * g$
     * <p>
     * Can overlap $h$ with $f$ or $g$.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by
     * $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * <li>$|g|$ bounded by
     * $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by
     * $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * </ul><p>
     * Notes on implementation strategy:
     * <p>
     * Using schoolbook multiplication. Karatsuba would save a little in some
     * cost models.
     * <p>
     * Most multiplications by 2 and 19 are 32-bit precomputations; cheaper than
     * 64-bit postcomputations.
     * <p>
     * There is one remaining multiplication by 19 in the carry chain; one *19
     * precomputation can be merged into this, but the resulting data flow is
     * considerably less clean.
     * <p>
     * There are 12 carries below. 10 of them are 2-way parallelizable and
     * vectorizable. Can get away with 11 carries, but then data flow is much
     * deeper.
     * <p>
     * With tighter constraints on inputs can squeeze carries into int32.
     *
     * @param val The field element to multiply.
     * @return The (reasonably reduced) field element this * val.
     */
    public FieldElement multiply(FieldElement val) {
        int[] g = ((Ed25519FieldElement)val).t;
        int g1_19 = 19 * g[1]; /* 1.959375*2^29 */
        int g2_19 = 19 * g[2]; /* 1.959375*2^30; still ok */
        int g3_19 = 19 * g[3];
        int g4_19 = 19 * g[4];
        int g5_19 = 19 * g[5];
        int g6_19 = 19 * g[6];
        int g7_19 = 19 * g[7];
        int g8_19 = 19 * g[8];
        int g9_19 = 19 * g[9];
        int f1_2 = 2 * t[1];
        int f3_2 = 2 * t[3];
        int f5_2 = 2 * t[5];
        int f7_2 = 2 * t[7];
        int f9_2 = 2 * t[9];
        long f0g0    = t[0] * (long) g[0];
        long f0g1    = t[0] * (long) g[1];
        long f0g2    = t[0] * (long) g[2];
        long f0g3    = t[0] * (long) g[3];
        long f0g4    = t[0] * (long) g[4];
        long f0g5    = t[0] * (long) g[5];
        long f0g6    = t[0] * (long) g[6];
        long f0g7    = t[0] * (long) g[7];
        long f0g8    = t[0] * (long) g[8];
        long f0g9    = t[0] * (long) g[9];
        long f1g0    = t[1] * (long) g[0];
        long f1g1_2  = f1_2 * (long) g[1];
        long f1g2    = t[1] * (long) g[2];
        long f1g3_2  = f1_2 * (long) g[3];
        long f1g4    = t[1] * (long) g[4];
        long f1g5_2  = f1_2 * (long) g[5];
        long f1g6    = t[1] * (long) g[6];
        long f1g7_2  = f1_2 * (long) g[7];
        long f1g8    = t[1] * (long) g[8];
        long f1g9_38 = f1_2 * (long) g9_19;
        long f2g0    = t[2] * (long) g[0];
        long f2g1    = t[2] * (long) g[1];
        long f2g2    = t[2] * (long) g[2];
        long f2g3    = t[2] * (long) g[3];
        long f2g4    = t[2] * (long) g[4];
        long f2g5    = t[2] * (long) g[5];
        long f2g6    = t[2] * (long) g[6];
        long f2g7    = t[2] * (long) g[7];
        long f2g8_19 = t[2] * (long) g8_19;
        long f2g9_19 = t[2] * (long) g9_19;
        long f3g0    = t[3] * (long) g[0];
        long f3g1_2  = f3_2 * (long) g[1];
        long f3g2    = t[3] * (long) g[2];
        long f3g3_2  = f3_2 * (long) g[3];
        long f3g4    = t[3] * (long) g[4];
        long f3g5_2  = f3_2 * (long) g[5];
        long f3g6    = t[3] * (long) g[6];
        long f3g7_38 = f3_2 * (long) g7_19;
        long f3g8_19 = t[3] * (long) g8_19;
        long f3g9_38 = f3_2 * (long) g9_19;
        long f4g0    = t[4] * (long) g[0];
        long f4g1    = t[4] * (long) g[1];
        long f4g2    = t[4] * (long) g[2];
        long f4g3    = t[4] * (long) g[3];
        long f4g4    = t[4] * (long) g[4];
        long f4g5    = t[4] * (long) g[5];
        long f4g6_19 = t[4] * (long) g6_19;
        long f4g7_19 = t[4] * (long) g7_19;
        long f4g8_19 = t[4] * (long) g8_19;
        long f4g9_19 = t[4] * (long) g9_19;
        long f5g0    = t[5] * (long) g[0];
        long f5g1_2  = f5_2 * (long) g[1];
        long f5g2    = t[5] * (long) g[2];
        long f5g3_2  = f5_2 * (long) g[3];
        long f5g4    = t[5] * (long) g[4];
        long f5g5_38 = f5_2 * (long) g5_19;
        long f5g6_19 = t[5] * (long) g6_19;
        long f5g7_38 = f5_2 * (long) g7_19;
        long f5g8_19 = t[5] * (long) g8_19;
        long f5g9_38 = f5_2 * (long) g9_19;
        long f6g0    = t[6] * (long) g[0];
        long f6g1    = t[6] * (long) g[1];
        long f6g2    = t[6] * (long) g[2];
        long f6g3    = t[6] * (long) g[3];
        long f6g4_19 = t[6] * (long) g4_19;
        long f6g5_19 = t[6] * (long) g5_19;
        long f6g6_19 = t[6] * (long) g6_19;
        long f6g7_19 = t[6] * (long) g7_19;
        long f6g8_19 = t[6] * (long) g8_19;
        long f6g9_19 = t[6] * (long) g9_19;
        long f7g0    = t[7] * (long) g[0];
        long f7g1_2  = f7_2 * (long) g[1];
        long f7g2    = t[7] * (long) g[2];
        long f7g3_38 = f7_2 * (long) g3_19;
        long f7g4_19 = t[7] * (long) g4_19;
        long f7g5_38 = f7_2 * (long) g5_19;
        long f7g6_19 = t[7] * (long) g6_19;
        long f7g7_38 = f7_2 * (long) g7_19;
        long f7g8_19 = t[7] * (long) g8_19;
        long f7g9_38 = f7_2 * (long) g9_19;
        long f8g0    = t[8] * (long) g[0];
        long f8g1    = t[8] * (long) g[1];
        long f8g2_19 = t[8] * (long) g2_19;
        long f8g3_19 = t[8] * (long) g3_19;
        long f8g4_19 = t[8] * (long) g4_19;
        long f8g5_19 = t[8] * (long) g5_19;
        long f8g6_19 = t[8] * (long) g6_19;
        long f8g7_19 = t[8] * (long) g7_19;
        long f8g8_19 = t[8] * (long) g8_19;
        long f8g9_19 = t[8] * (long) g9_19;
        long f9g0    = t[9] * (long) g[0];
        long f9g1_38 = f9_2 * (long) g1_19;
        long f9g2_19 = t[9] * (long) g2_19;
        long f9g3_38 = f9_2 * (long) g3_19;
        long f9g4_19 = t[9] * (long) g4_19;
        long f9g5_38 = f9_2 * (long) g5_19;
        long f9g6_19 = t[9] * (long) g6_19;
        long f9g7_38 = f9_2 * (long) g7_19;
        long f9g8_19 = t[9] * (long) g8_19;
        long f9g9_38 = f9_2 * (long) g9_19;

        /**
         * Remember: 2^255 congruent 19 modulo p.
         * h = h0 * 2^0 + h1 * 2^26 + h2 * 2^(26+25) + h3 * 2^(26+25+26) + ... + h9 * 2^(5*26+5*25).
         * So to get the real number we would have to multiply the coefficients with the corresponding powers of 2.
         * To get an idea what is going on below, look at the calculation of h0:
         * h0 is the coefficient to the power 2^0 so it collects (sums) all products that have the power 2^0.
         * f0 * g0 really is f0 * 2^0 * g0 * 2^0 = (f0 * g0) * 2^0.
         * f1 * g9 really is f1 * 2^26 * g9 * 2^230 = f1 * g9 * 2^256 = 2 * f1 * g9 * 2^255 congruent 2 * 19 * f1 * g9 * 2^0 modulo p.
         * f2 * g8 really is f2 * 2^51 * g8 * 2^204 = f2 * g8 * 2^255 congruent 19 * f2 * g8 * 2^0 modulo p.
         * and so on...
         */
        long h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
        long h1 = f0g1 + f1g0    + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
        long h2 = f0g2 + f1g1_2  + f2g0    + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
        long h3 = f0g3 + f1g2    + f2g1    + f3g0    + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        long h4 = f0g4 + f1g3_2  + f2g2    + f3g1_2  + f4g0    + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        long h5 = f0g5 + f1g4    + f2g3    + f3g2    + f4g1    + f5g0    + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        long h6 = f0g6 + f1g5_2  + f2g4    + f3g3_2  + f4g2    + f5g1_2  + f6g0    + f7g9_38 + f8g8_19 + f9g7_38;
        long h7 = f0g7 + f1g6    + f2g5    + f3g4    + f4g3    + f5g2    + f6g1    + f7g0    + f8g9_19 + f9g8_19;
        long h8 = f0g8 + f1g7_2  + f2g6    + f3g5_2  + f4g4    + f5g3_2  + f6g2    + f7g1_2  + f8g0    + f9g9_38;
        long h9 = f0g9 + f1g8    + f2g7    + f3g6    + f4g5    + f5g4    + f6g3    + f7g2    + f8g1    + f9g0;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        /*
        |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
          i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
        |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
          i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
        */

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        /* |h0| <= 2^25 */
        /* |h4| <= 2^25 */
        /* |h1| <= 1.71*2^59 */
        /* |h5| <= 1.71*2^59 */

        carry1 = (h1 + (long) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (long) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        /* |h1| <= 2^24; from now on fits into int32 */
        /* |h5| <= 2^24; from now on fits into int32 */
        /* |h2| <= 1.41*2^60 */
        /* |h6| <= 1.41*2^60 */

        carry2 = (h2 + (long) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (long) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        /* |h2| <= 2^25; from now on fits into int32 unchanged */
        /* |h6| <= 2^25; from now on fits into int32 unchanged */
        /* |h3| <= 1.71*2^59 */
        /* |h7| <= 1.71*2^59 */

        carry3 = (h3 + (long) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (long) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
        /* |h3| <= 2^24; from now on fits into int32 unchanged */
        /* |h7| <= 2^24; from now on fits into int32 unchanged */
        /* |h4| <= 1.72*2^34 */
        /* |h8| <= 1.41*2^60 */

        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (long) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
        /* |h4| <= 2^25; from now on fits into int32 unchanged */
        /* |h8| <= 2^25; from now on fits into int32 unchanged */
        /* |h5| <= 1.01*2^24 */
        /* |h9| <= 1.71*2^59 */

        carry9 = (h9 + (long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        /* |h9| <= 2^24; from now on fits into int32 unchanged */
        /* |h0| <= 1.1*2^39 */

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        /* |h0| <= 2^25; from now on fits into int32 unchanged */
        /* |h1| <= 1.01*2^24 */

        int[] h = new int[10];
        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = f * f$
     * <p>
     * Can overlap $h$ with $f$.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * </ul><p>
     * See {@link #multiply(FieldElement)} for discussion
     * of implementation strategy.
     *
     * @return The (reasonably reduced) square of this field element.
     */
    public FieldElement square() {
        int f0 = t[0];
        int f1 = t[1];
        int f2 = t[2];
        int f3 = t[3];
        int f4 = t[4];
        int f5 = t[5];
        int f6 = t[6];
        int f7 = t[7];
        int f8 = t[8];
        int f9 = t[9];
        int f0_2 = 2 * f0;
        int f1_2 = 2 * f1;
        int f2_2 = 2 * f2;
        int f3_2 = 2 * f3;
        int f4_2 = 2 * f4;
        int f5_2 = 2 * f5;
        int f6_2 = 2 * f6;
        int f7_2 = 2 * f7;
        int f5_38 = 38 * f5; /* 1.959375*2^30 */
        int f6_19 = 19 * f6; /* 1.959375*2^30 */
        int f7_38 = 38 * f7; /* 1.959375*2^30 */
        int f8_19 = 19 * f8; /* 1.959375*2^30 */
        int f9_38 = 38 * f9; /* 1.959375*2^30 */
        long f0f0    = f0   * (long) f0;
        long f0f1_2  = f0_2 * (long) f1;
        long f0f2_2  = f0_2 * (long) f2;
        long f0f3_2  = f0_2 * (long) f3;
        long f0f4_2  = f0_2 * (long) f4;
        long f0f5_2  = f0_2 * (long) f5;
        long f0f6_2  = f0_2 * (long) f6;
        long f0f7_2  = f0_2 * (long) f7;
        long f0f8_2  = f0_2 * (long) f8;
        long f0f9_2  = f0_2 * (long) f9;
        long f1f1_2  = f1_2 * (long) f1;
        long f1f2_2  = f1_2 * (long) f2;
        long f1f3_4  = f1_2 * (long) f3_2;
        long f1f4_2  = f1_2 * (long) f4;
        long f1f5_4  = f1_2 * (long) f5_2;
        long f1f6_2  = f1_2 * (long) f6;
        long f1f7_4  = f1_2 * (long) f7_2;
        long f1f8_2  = f1_2 * (long) f8;
        long f1f9_76 = f1_2 * (long) f9_38;
        long f2f2    = f2   * (long) f2;
        long f2f3_2  = f2_2 * (long) f3;
        long f2f4_2  = f2_2 * (long) f4;
        long f2f5_2  = f2_2 * (long) f5;
        long f2f6_2  = f2_2 * (long) f6;
        long f2f7_2  = f2_2 * (long) f7;
        long f2f8_38 = f2_2 * (long) f8_19;
        long f2f9_38 = f2   * (long) f9_38;
        long f3f3_2  = f3_2 * (long) f3;
        long f3f4_2  = f3_2 * (long) f4;
        long f3f5_4  = f3_2 * (long) f5_2;
        long f3f6_2  = f3_2 * (long) f6;
        long f3f7_76 = f3_2 * (long) f7_38;
        long f3f8_38 = f3_2 * (long) f8_19;
        long f3f9_76 = f3_2 * (long) f9_38;
        long f4f4    = f4   * (long) f4;
        long f4f5_2  = f4_2 * (long) f5;
        long f4f6_38 = f4_2 * (long) f6_19;
        long f4f7_38 = f4   * (long) f7_38;
        long f4f8_38 = f4_2 * (long) f8_19;
        long f4f9_38 = f4   * (long) f9_38;
        long f5f5_38 = f5   * (long) f5_38;
        long f5f6_38 = f5_2 * (long) f6_19;
        long f5f7_76 = f5_2 * (long) f7_38;
        long f5f8_38 = f5_2 * (long) f8_19;
        long f5f9_76 = f5_2 * (long) f9_38;
        long f6f6_19 = f6   * (long) f6_19;
        long f6f7_38 = f6   * (long) f7_38;
        long f6f8_38 = f6_2 * (long) f8_19;
        long f6f9_38 = f6   * (long) f9_38;
        long f7f7_38 = f7   * (long) f7_38;
        long f7f8_38 = f7_2 * (long) f8_19;
        long f7f9_76 = f7_2 * (long) f9_38;
        long f8f8_19 = f8   * (long) f8_19;
        long f8f9_38 = f8   * (long) f9_38;
        long f9f9_38 = f9   * (long) f9_38;

        /**
         * Same procedure as in multiply, but this time we have a higher symmetry leading to less summands.
         * e.g. f1f9_76 really stands for f1 * 2^26 * f9 * 2^230 + f9 * 2^230 + f1 * 2^26 congruent 2 * 2 * 19 * f1 * f9  2^0 modulo p.
         */
        long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;
        long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38;
        long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

        carry1 = (h1 + (long) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (long) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

        carry2 = (h2 + (long) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (long) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

        carry3 = (h3 + (long) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (long) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (long) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        carry9 = (h9 + (long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

        int[] h = new int[10];
        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = 2 * f * f$
     * <p>
     * Can overlap $h$ with $f$.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * </ul><p>
     * See {@link #multiply(FieldElement)} for discussion
     * of implementation strategy.
     *
     * @return The (reasonably reduced) square of this field element times 2.
     */
    public FieldElement squareAndDouble() {
        int f0 = t[0];
        int f1 = t[1];
        int f2 = t[2];
        int f3 = t[3];
        int f4 = t[4];
        int f5 = t[5];
        int f6 = t[6];
        int f7 = t[7];
        int f8 = t[8];
        int f9 = t[9];
        int f0_2 = 2 * f0;
        int f1_2 = 2 * f1;
        int f2_2 = 2 * f2;
        int f3_2 = 2 * f3;
        int f4_2 = 2 * f4;
        int f5_2 = 2 * f5;
        int f6_2 = 2 * f6;
        int f7_2 = 2 * f7;
        int f5_38 = 38 * f5; /* 1.959375*2^30 */
        int f6_19 = 19 * f6; /* 1.959375*2^30 */
        int f7_38 = 38 * f7; /* 1.959375*2^30 */
        int f8_19 = 19 * f8; /* 1.959375*2^30 */
        int f9_38 = 38 * f9; /* 1.959375*2^30 */
        long f0f0    = f0   * (long) f0;
        long f0f1_2  = f0_2 * (long) f1;
        long f0f2_2  = f0_2 * (long) f2;
        long f0f3_2  = f0_2 * (long) f3;
        long f0f4_2  = f0_2 * (long) f4;
        long f0f5_2  = f0_2 * (long) f5;
        long f0f6_2  = f0_2 * (long) f6;
        long f0f7_2  = f0_2 * (long) f7;
        long f0f8_2  = f0_2 * (long) f8;
        long f0f9_2  = f0_2 * (long) f9;
        long f1f1_2  = f1_2 * (long) f1;
        long f1f2_2  = f1_2 * (long) f2;
        long f1f3_4  = f1_2 * (long) f3_2;
        long f1f4_2  = f1_2 * (long) f4;
        long f1f5_4  = f1_2 * (long) f5_2;
        long f1f6_2  = f1_2 * (long) f6;
        long f1f7_4  = f1_2 * (long) f7_2;
        long f1f8_2  = f1_2 * (long) f8;
        long f1f9_76 = f1_2 * (long) f9_38;
        long f2f2    = f2   * (long) f2;
        long f2f3_2  = f2_2 * (long) f3;
        long f2f4_2  = f2_2 * (long) f4;
        long f2f5_2  = f2_2 * (long) f5;
        long f2f6_2  = f2_2 * (long) f6;
        long f2f7_2  = f2_2 * (long) f7;
        long f2f8_38 = f2_2 * (long) f8_19;
        long f2f9_38 = f2   * (long) f9_38;
        long f3f3_2  = f3_2 * (long) f3;
        long f3f4_2  = f3_2 * (long) f4;
        long f3f5_4  = f3_2 * (long) f5_2;
        long f3f6_2  = f3_2 * (long) f6;
        long f3f7_76 = f3_2 * (long) f7_38;
        long f3f8_38 = f3_2 * (long) f8_19;
        long f3f9_76 = f3_2 * (long) f9_38;
        long f4f4    = f4   * (long) f4;
        long f4f5_2  = f4_2 * (long) f5;
        long f4f6_38 = f4_2 * (long) f6_19;
        long f4f7_38 = f4   * (long) f7_38;
        long f4f8_38 = f4_2 * (long) f8_19;
        long f4f9_38 = f4   * (long) f9_38;
        long f5f5_38 = f5   * (long) f5_38;
        long f5f6_38 = f5_2 * (long) f6_19;
        long f5f7_76 = f5_2 * (long) f7_38;
        long f5f8_38 = f5_2 * (long) f8_19;
        long f5f9_76 = f5_2 * (long) f9_38;
        long f6f6_19 = f6   * (long) f6_19;
        long f6f7_38 = f6   * (long) f7_38;
        long f6f8_38 = f6_2 * (long) f8_19;
        long f6f9_38 = f6   * (long) f9_38;
        long f7f7_38 = f7   * (long) f7_38;
        long f7f8_38 = f7_2 * (long) f8_19;
        long f7f9_76 = f7_2 * (long) f9_38;
        long f8f8_19 = f8   * (long) f8_19;
        long f8f9_38 = f8   * (long) f9_38;
        long f9f9_38 = f9   * (long) f9_38;
        long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;
        long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38;
        long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        h0 += h0;
        h1 += h1;
        h2 += h2;
        h3 += h3;
        h4 += h4;
        h5 += h5;
        h6 += h6;
        h7 += h7;
        h8 += h8;
        h9 += h9;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

        carry1 = (h1 + (long) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (long) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

        carry2 = (h2 + (long) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (long) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

        carry3 = (h3 + (long) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (long) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (long) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        carry9 = (h9 + (long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

        int[] h = new int[10];
        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;
        return new Ed25519FieldElement(f, h);
    }

    /**
     * Invert this field element.
     * <p>
     * The inverse is found via Fermat's little theorem:<br>
     * $a^p \cong a \mod p$ and therefore $a^{(p-2)} \cong a^{-1} \mod p$
     *
     * @return The inverse of this field element.
     */
    public FieldElement invert() {
        FieldElement t0, t1, t2, t3;

        // 2 == 2 * 1
        t0 = square();

        // 4 == 2 * 2
        t1 = t0.square();

        // 8 == 2 * 4
        t1 = t1.square();

        // 9 == 8 + 1
        t1 = multiply(t1);

        // 11 == 9 + 2
        t0 = t0.multiply(t1);

        // 22 == 2 * 11
        t2 = t0.square();

        // 31 == 22 + 9
        t1 = t1.multiply(t2);

        // 2^6 - 2^1
        t2 = t1.square();

        // 2^10 - 2^5
        for (int i = 1; i < 5; ++i) {
            t2 = t2.square();
        }

        // 2^10 - 2^0
        t1 = t2.multiply(t1);

        // 2^11 - 2^1
        t2 = t1.square();

        // 2^20 - 2^10
        for (int i = 1; i < 10; ++i) {
            t2 = t2.square();
        }

        // 2^20 - 2^0
        t2 = t2.multiply(t1);

        // 2^21 - 2^1
        t3 = t2.square();

        // 2^40 - 2^20
        for (int i = 1; i < 20; ++i) {
            t3 = t3.square();
        }

        // 2^40 - 2^0
        t2 = t3.multiply(t2);

        // 2^41 - 2^1
        t2 = t2.square();

        // 2^50 - 2^10
        for (int i = 1; i < 10; ++i) {
            t2 = t2.square();
        }

        // 2^50 - 2^0
        t1 = t2.multiply(t1);

        // 2^51 - 2^1
        t2 = t1.square();

        // 2^100 - 2^50
        for (int i = 1; i < 50; ++i) {
            t2 = t2.square();
        }

        // 2^100 - 2^0
        t2 = t2.multiply(t1);

        // 2^101 - 2^1
        t3 = t2.square();

        // 2^200 - 2^100
        for (int i = 1; i < 100; ++i) {
            t3 = t3.square();
        }

        // 2^200 - 2^0
        t2 = t3.multiply(t2);

        // 2^201 - 2^1
        t2 = t2.square();

        // 2^250 - 2^50
        for (int i = 1; i < 50; ++i) {
            t2 = t2.square();
        }

        // 2^250 - 2^0
        t1 = t2.multiply(t1);

        // 2^251 - 2^1
        t1 = t1.square();

        // 2^255 - 2^5
        for (int i = 1; i < 5; ++i) {
            t1 = t1.square();
        }

        // 2^255 - 21
        return t1.multiply(t0);
    }

    /**
     * Gets this field element to the power of $(2^{252} - 3)$.
     * This is a helper function for calculating the square root.
     * <p>
     * TODO-CR BR: I think it makes sense to have a sqrt function.
     *
     * @return This field element to the power of $(2^{252} - 3)$.
     */
    public FieldElement pow22523() {
        FieldElement t0, t1, t2;

        // 2 == 2 * 1
        t0 = square();

        // 4 == 2 * 2
        t1 = t0.square();

        // 8 == 2 * 4
        t1 = t1.square();

        // z9 = z1*z8
        t1 = multiply(t1);

        // 11 == 9 + 2
        t0 = t0.multiply(t1);

        // 22 == 2 * 11
        t0 = t0.square();

        // 31 == 22 + 9
        t0 = t1.multiply(t0);

        // 2^6 - 2^1
        t1 = t0.square();

        // 2^10 - 2^5
        for (int i = 1; i < 5; ++i) {
            t1 = t1.square();
        }

        // 2^10 - 2^0
        t0 = t1.multiply(t0);

        // 2^11 - 2^1
        t1 = t0.square();

        // 2^20 - 2^10
        for (int i = 1; i < 10; ++i) {
            t1 = t1.square();
        }

        // 2^20 - 2^0
        t1 = t1.multiply(t0);

        // 2^21 - 2^1
        t2 = t1.square();

        // 2^40 - 2^20
        for (int i = 1; i < 20; ++i) {
            t2 = t2.square();
        }

        // 2^40 - 2^0
        t1 = t2.multiply(t1);

        // 2^41 - 2^1
        t1 = t1.square();

        // 2^50 - 2^10
        for (int i = 1; i < 10; ++i) {
            t1 = t1.square();
        }

        // 2^50 - 2^0
        t0 = t1.multiply(t0);

        // 2^51 - 2^1
        t1 = t0.square();

        // 2^100 - 2^50
        for (int i = 1; i < 50; ++i) {
            t1 = t1.square();
        }

        // 2^100 - 2^0
        t1 = t1.multiply(t0);

        // 2^101 - 2^1
        t2 = t1.square();

        // 2^200 - 2^100
        for (int i = 1; i < 100; ++i) {
            t2 = t2.square();
        }

        // 2^200 - 2^0
        t1 = t2.multiply(t1);

        // 2^201 - 2^1
        t1 = t1.square();

        // 2^250 - 2^50
        for (int i = 1; i < 50; ++i) {
            t1 = t1.square();
        }

        // 2^250 - 2^0
        t0 = t1.multiply(t0);

        // 2^251 - 2^1
        t0 = t0.square();

        // 2^252 - 2^2
        t0 = t0.square();

        // 2^252 - 3
        return multiply(t0);
    }

    /**
     * Constant-time conditional move. Well, actually it is a conditional copy.
     * Logic is inspired by the SUPERCOP implementation at:
     *   https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref10/fe_cmov.c
     *
     * @param val the other field element.
     * @param b must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of val if $b == 1$.
     */
    @Override
    public FieldElement cmov(FieldElement val, int b) {
        Ed25519FieldElement that = (Ed25519FieldElement) val;
        b = -b;
        int[] result = new int[10];
        for (int i = 0; i < 10; i++) {
            result[i] = this.t[i];
            int x = this.t[i] ^ that.t[i];
            x &= b;
            result[i] ^= x;
        }
        return new Ed25519FieldElement(this.f, result);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(t);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Ed25519FieldElement))
            return false;
        Ed25519FieldElement fe = (Ed25519FieldElement) obj;
        return 1==Utils.equal(toByteArray(), fe.toByteArray());
    }

    @Override
    public String toString() {
        return "[Ed25519FieldElement val="+Utils.bytesToHex(toByteArray())+"]";
    }
}
