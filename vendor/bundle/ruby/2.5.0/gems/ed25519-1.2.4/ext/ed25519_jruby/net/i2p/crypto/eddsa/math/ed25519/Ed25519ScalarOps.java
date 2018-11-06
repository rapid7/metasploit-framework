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

import net.i2p.crypto.eddsa.math.ScalarOps;
import static net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding.load_3;
import static net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding.load_4;

/**
 * Class for reducing a huge integer modulo the group order q and
 * doing a combined multiply plus add plus reduce operation.
 * <p>
 * $q = 2^{252} + 27742317777372353535851937790883648493$.
 * <p>
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
public class Ed25519ScalarOps implements ScalarOps {

    /**
     * Reduction modulo the group order $q$.
     * <p>
     * Input:
     *   $s[0]+256*s[1]+\dots+256^{63}*s[63] = s$
     * <p>
     * Output:
     *   $s[0]+256*s[1]+\dots+256^{31}*s[31] = s \bmod q$
     *   where $q = 2^{252} + 27742317777372353535851937790883648493$.
     */
    public byte[] reduce(byte[] s) {
        // s0,..., s22 have 21 bits, s23 has 29 bits
        long s0 = 0x1FFFFF & load_3(s, 0);
        long s1 = 0x1FFFFF & (load_4(s, 2) >> 5);
        long s2 = 0x1FFFFF & (load_3(s, 5) >> 2);
        long s3 = 0x1FFFFF & (load_4(s, 7) >> 7);
        long s4 = 0x1FFFFF & (load_4(s, 10) >> 4);
        long s5 = 0x1FFFFF & (load_3(s, 13) >> 1);
        long s6 = 0x1FFFFF & (load_4(s, 15) >> 6);
        long s7 = 0x1FFFFF & (load_3(s, 18) >> 3);
        long s8 = 0x1FFFFF & load_3(s, 21);
        long s9 = 0x1FFFFF & (load_4(s, 23) >> 5);
        long s10 = 0x1FFFFF & (load_3(s, 26) >> 2);
        long s11 = 0x1FFFFF & (load_4(s, 28) >> 7);
        long s12 = 0x1FFFFF & (load_4(s, 31) >> 4);
        long s13 = 0x1FFFFF & (load_3(s, 34) >> 1);
        long s14 = 0x1FFFFF & (load_4(s, 36) >> 6);
        long s15 = 0x1FFFFF & (load_3(s, 39) >> 3);
        long s16 = 0x1FFFFF & load_3(s, 42);
        long s17 = 0x1FFFFF & (load_4(s, 44) >> 5);
        long s18 = 0x1FFFFF & (load_3(s, 47) >> 2);
        long s19 = 0x1FFFFF & (load_4(s, 49) >> 7);
        long s20 = 0x1FFFFF & (load_4(s, 52) >> 4);
        long s21 = 0x1FFFFF & (load_3(s, 55) >> 1);
        long s22 = 0x1FFFFF & (load_4(s, 57) >> 6);
        long s23 = (load_4(s, 60) >> 3);
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
        long carry10;
        long carry11;
        long carry12;
        long carry13;
        long carry14;
        long carry15;
        long carry16;

        /**
         * Lots of magic numbers :)
         * To understand what's going on below, note that
         *
         * (1) q = 2^252 + q0 where q0 = 27742317777372353535851937790883648493.
         * (2) s11 is the coefficient of 2^(11*21), s23 is the coefficient of 2^(^23*21) and 2^252 = 2^((23-11) * 21)).
         * (3) 2^252 congruent -q0 modulo q.
         * (4) -q0 = 666643 * 2^0 + 470296 * 2^21 + 654183 * 2^(2*21) - 997805 * 2^(3*21) + 136657 * 2^(4*21) - 683901 * 2^(5*21)
         *
         * Thus
         * s23 * 2^(23*11) = s23 * 2^(12*21) * 2^(11*21) = s3 * 2^252 * 2^(11*21) congruent
         * s23 * (666643 * 2^0 + 470296 * 2^21 + 654183 * 2^(2*21) - 997805 * 2^(3*21) + 136657 * 2^(4*21) - 683901 * 2^(5*21)) * 2^(11*21) modulo q =
         * s23 * (666643 * 2^(11*21) + 470296 * 2^(12*21) + 654183 * 2^(13*21) - 997805 * 2^(14*21) + 136657 * 2^(15*21) - 683901 * 2^(16*21)).
         *
         * The same procedure is then applied for s22,...,s18.
         */
        s11 += s23 * 666643;
        s12 += s23 * 470296;
        s13 += s23 * 654183;
        s14 -= s23 * 997805;
        s15 += s23 * 136657;
        s16 -= s23 * 683901;
        // not used again
        //s23 = 0;

        s10 += s22 * 666643;
        s11 += s22 * 470296;
        s12 += s22 * 654183;
        s13 -= s22 * 997805;
        s14 += s22 * 136657;
        s15 -= s22 * 683901;
        // not used again
        //s22 = 0;

        s9 += s21 * 666643;
        s10 += s21 * 470296;
        s11 += s21 * 654183;
        s12 -= s21 * 997805;
        s13 += s21 * 136657;
        s14 -= s21 * 683901;
        // not used again
        //s21 = 0;

        s8 += s20 * 666643;
        s9 += s20 * 470296;
        s10 += s20 * 654183;
        s11 -= s20 * 997805;
        s12 += s20 * 136657;
        s13 -= s20 * 683901;
        // not used again
        //s20 = 0;

        s7 += s19 * 666643;
        s8 += s19 * 470296;
        s9 += s19 * 654183;
        s10 -= s19 * 997805;
        s11 += s19 * 136657;
        s12 -= s19 * 683901;
        // not used again
        //s19 = 0;

        s6 += s18 * 666643;
        s7 += s18 * 470296;
        s8 += s18 * 654183;
        s9 -= s18 * 997805;
        s10 += s18 * 136657;
        s11 -= s18 * 683901;
        // not used again
        //s18 = 0;

        /**
         * Time to reduce the coefficient in order not to get an overflow.
         */
        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

        /**
         * Continue with above procedure.
         */
        s5 += s17 * 666643;
        s6 += s17 * 470296;
        s7 += s17 * 654183;
        s8 -= s17 * 997805;
        s9 += s17 * 136657;
        s10 -= s17 * 683901;
        // not used again
        //s17 = 0;

        s4 += s16 * 666643;
        s5 += s16 * 470296;
        s6 += s16 * 654183;
        s7 -= s16 * 997805;
        s8 += s16 * 136657;
        s9 -= s16 * 683901;
        // not used again
        //s16 = 0;

        s3 += s15 * 666643;
        s4 += s15 * 470296;
        s5 += s15 * 654183;
        s6 -= s15 * 997805;
        s7 += s15 * 136657;
        s8 -= s15 * 683901;
        // not used again
        //s15 = 0;

        s2 += s14 * 666643;
        s3 += s14 * 470296;
        s4 += s14 * 654183;
        s5 -= s14 * 997805;
        s6 += s14 * 136657;
        s7 -= s14 * 683901;
        // not used again
        //s14 = 0;

        s1 += s13 * 666643;
        s2 += s13 * 470296;
        s3 += s13 * 654183;
        s4 -= s13 * 997805;
        s5 += s13 * 136657;
        s6 -= s13 * 683901;
        // not used again
        //s13 = 0;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        // set below
        //s12 = 0;

        /**
         * Reduce coefficients again.
         */
        carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

        carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        //carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 = carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        // set below
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        //carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 >> 21; s12 = carry11; s11 -= carry11 << 21;

        // TODO-CR BR: Is it really needed to do it TWO times? (it doesn't hurt, just a question).
        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        // not used again
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        // s0, ..., s11 got 21 bits each.
        byte[] result = new byte[32];
        result[0] = (byte) s0;
        result[1] = (byte) (s0 >> 8);
        result[2] = (byte) ((s0 >> 16) | (s1 << 5));
        result[3] = (byte) (s1 >> 3);
        result[4] = (byte) (s1 >> 11);
        result[5] = (byte) ((s1 >> 19) | (s2 << 2));
        result[6] = (byte) (s2 >> 6);
        result[7] = (byte) ((s2 >> 14) | (s3 << 7));
        result[8] = (byte) (s3 >> 1);
        result[9] = (byte) (s3 >> 9);
        result[10] = (byte) ((s3 >> 17) | (s4 << 4));
        result[11] = (byte) (s4 >> 4);
        result[12] = (byte) (s4 >> 12);
        result[13] = (byte) ((s4 >> 20) | (s5 << 1));
        result[14] = (byte) (s5 >> 7);
        result[15] = (byte) ((s5 >> 15) | (s6 << 6));
        result[16] = (byte) (s6 >> 2);
        result[17] = (byte) (s6 >> 10);
        result[18] = (byte) ((s6 >> 18) | (s7 << 3));
        result[19] = (byte) (s7 >> 5);
        result[20] = (byte) (s7 >> 13);
        result[21] = (byte) s8;
        result[22] = (byte) (s8 >> 8);
        result[23] = (byte) ((s8 >> 16) | (s9 << 5));
        result[24] = (byte) (s9 >> 3);
        result[25] = (byte) (s9 >> 11);
        result[26] = (byte) ((s9 >> 19) | (s10 << 2));
        result[27] = (byte) (s10 >> 6);
        result[28] = (byte) ((s10 >> 14) | (s11 << 7));
        result[29] = (byte) (s11 >> 1);
        result[30] = (byte) (s11 >> 9);
        result[31] = (byte) (s11 >> 17);
        return result;
    }


    /**
     * $(ab+c) \bmod q$
     * <p>
     * Input:
     * </p><ul>
     * <li>$a[0]+256*a[1]+\dots+256^{31}*a[31] = a$
     * <li>$b[0]+256*b[1]+\dots+256^{31}*b[31] = b$
     * <li>$c[0]+256*c[1]+\dots+256^{31}*c[31] = c$
     * </ul><p>
     * Output:
     *   $result[0]+256*result[1]+\dots+256^{31}*result[31] = (ab+c) \bmod q$
     *   where $q = 2^{252} + 27742317777372353535851937790883648493$.
     * <p>
     * See the comments in {@link #reduce(byte[])} for an explanation of the algorithm.
     */
    public byte[] multiplyAndAdd(byte[] a, byte[] b, byte[] c) {
        long a0 = 0x1FFFFF & load_3(a, 0);
        long a1 = 0x1FFFFF & (load_4(a, 2) >> 5);
        long a2 = 0x1FFFFF & (load_3(a, 5) >> 2);
        long a3 = 0x1FFFFF & (load_4(a, 7) >> 7);
        long a4 = 0x1FFFFF & (load_4(a, 10) >> 4);
        long a5 = 0x1FFFFF & (load_3(a, 13) >> 1);
        long a6 = 0x1FFFFF & (load_4(a, 15) >> 6);
        long a7 = 0x1FFFFF & (load_3(a, 18) >> 3);
        long a8 = 0x1FFFFF & load_3(a, 21);
        long a9 = 0x1FFFFF & (load_4(a, 23) >> 5);
        long a10 = 0x1FFFFF & (load_3(a, 26) >> 2);
        long a11 = (load_4(a, 28) >> 7);
        long b0 = 0x1FFFFF & load_3(b, 0);
        long b1 = 0x1FFFFF & (load_4(b, 2) >> 5);
        long b2 = 0x1FFFFF & (load_3(b, 5) >> 2);
        long b3 = 0x1FFFFF & (load_4(b, 7) >> 7);
        long b4 = 0x1FFFFF & (load_4(b, 10) >> 4);
        long b5 = 0x1FFFFF & (load_3(b, 13) >> 1);
        long b6 = 0x1FFFFF & (load_4(b, 15) >> 6);
        long b7 = 0x1FFFFF & (load_3(b, 18) >> 3);
        long b8 = 0x1FFFFF & load_3(b, 21);
        long b9 = 0x1FFFFF & (load_4(b, 23) >> 5);
        long b10 = 0x1FFFFF & (load_3(b, 26) >> 2);
        long b11 = (load_4(b, 28) >> 7);
        long c0 = 0x1FFFFF & load_3(c, 0);
        long c1 = 0x1FFFFF & (load_4(c, 2) >> 5);
        long c2 = 0x1FFFFF & (load_3(c, 5) >> 2);
        long c3 = 0x1FFFFF & (load_4(c, 7) >> 7);
        long c4 = 0x1FFFFF & (load_4(c, 10) >> 4);
        long c5 = 0x1FFFFF & (load_3(c, 13) >> 1);
        long c6 = 0x1FFFFF & (load_4(c, 15) >> 6);
        long c7 = 0x1FFFFF & (load_3(c, 18) >> 3);
        long c8 = 0x1FFFFF & load_3(c, 21);
        long c9 = 0x1FFFFF & (load_4(c, 23) >> 5);
        long c10 = 0x1FFFFF & (load_3(c, 26) >> 2);
        long c11 = (load_4(c, 28) >> 7);
        long s0;
        long s1;
        long s2;
        long s3;
        long s4;
        long s5;
        long s6;
        long s7;
        long s8;
        long s9;
        long s10;
        long s11;
        long s12;
        long s13;
        long s14;
        long s15;
        long s16;
        long s17;
        long s18;
        long s19;
        long s20;
        long s21;
        long s22;
        long s23;
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
        long carry10;
        long carry11;
        long carry12;
        long carry13;
        long carry14;
        long carry15;
        long carry16;
        long carry17;
        long carry18;
        long carry19;
        long carry20;
        long carry21;
        long carry22;

        s0 = c0 + a0*b0;
        s1 = c1 + a0*b1 + a1*b0;
        s2 = c2 + a0*b2 + a1*b1 + a2*b0;
        s3 = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0;
        s4 = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
        s5 = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0;
        s6 = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0;
        s7 = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0;
        s8 = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0;
        s9 = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
        s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0;
        s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0;
        s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1;
        s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2;
        s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3;
        s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4;
        s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5;
        s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6;
        s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7;
        s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8;
        s20 = a9*b11 + a10*b10 + a11*b9;
        s21 = a10*b11 + a11*b10;
        s22 = a11*b11;
        // set below
        //s23 = 0;

        carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
        carry18 = (s18 + (1<<20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
        carry20 = (s20 + (1<<20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
        //carry22 = (s22 + (1<<20)) >> 21; s23 += carry22; s22 -= carry22 << 21;
        carry22 = (s22 + (1<<20)) >> 21; s23 = carry22; s22 -= carry22 << 21;

        carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
        carry17 = (s17 + (1<<20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
        carry19 = (s19 + (1<<20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
        carry21 = (s21 + (1<<20)) >> 21; s22 += carry21; s21 -= carry21 << 21;

        s11 += s23 * 666643;
        s12 += s23 * 470296;
        s13 += s23 * 654183;
        s14 -= s23 * 997805;
        s15 += s23 * 136657;
        s16 -= s23 * 683901;
        // not used again
        //s23 = 0;

        s10 += s22 * 666643;
        s11 += s22 * 470296;
        s12 += s22 * 654183;
        s13 -= s22 * 997805;
        s14 += s22 * 136657;
        s15 -= s22 * 683901;
        // not used again
        //s22 = 0;

        s9 += s21 * 666643;
        s10 += s21 * 470296;
        s11 += s21 * 654183;
        s12 -= s21 * 997805;
        s13 += s21 * 136657;
        s14 -= s21 * 683901;
        // not used again
        //s21 = 0;

        s8 += s20 * 666643;
        s9 += s20 * 470296;
        s10 += s20 * 654183;
        s11 -= s20 * 997805;
        s12 += s20 * 136657;
        s13 -= s20 * 683901;
        // not used again
        //s20 = 0;

        s7 += s19 * 666643;
        s8 += s19 * 470296;
        s9 += s19 * 654183;
        s10 -= s19 * 997805;
        s11 += s19 * 136657;
        s12 -= s19 * 683901;
        // not used again
        //s19 = 0;

        s6 += s18 * 666643;
        s7 += s18 * 470296;
        s8 += s18 * 654183;
        s9 -= s18 * 997805;
        s10 += s18 * 136657;
        s11 -= s18 * 683901;
        // not used again
        //s18 = 0;

        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

        s5 += s17 * 666643;
        s6 += s17 * 470296;
        s7 += s17 * 654183;
        s8 -= s17 * 997805;
        s9 += s17 * 136657;
        s10 -= s17 * 683901;
        // not used again
        //s17 = 0;

        s4 += s16 * 666643;
        s5 += s16 * 470296;
        s6 += s16 * 654183;
        s7 -= s16 * 997805;
        s8 += s16 * 136657;
        s9 -= s16 * 683901;
        // not used again
        //s16 = 0;

        s3 += s15 * 666643;
        s4 += s15 * 470296;
        s5 += s15 * 654183;
        s6 -= s15 * 997805;
        s7 += s15 * 136657;
        s8 -= s15 * 683901;
        // not used again
        //s15 = 0;

        s2 += s14 * 666643;
        s3 += s14 * 470296;
        s4 += s14 * 654183;
        s5 -= s14 * 997805;
        s6 += s14 * 136657;
        s7 -= s14 * 683901;
        // not used again
        //s14 = 0;

        s1 += s13 * 666643;
        s2 += s13 * 470296;
        s3 += s13 * 654183;
        s4 -= s13 * 997805;
        s5 += s13 * 136657;
        s6 -= s13 * 683901;
        // not used again
        //s13 = 0;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        // set below
        //s12 = 0;

        carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

        carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        //carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 = carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        // set below
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        //carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 >> 21; s12 = carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        // not used again
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        byte[] result = new byte[32];
        result[0] = (byte) s0;
        result[1] = (byte) (s0 >> 8);
        result[2] = (byte) ((s0 >> 16) | (s1 << 5));
        result[3] = (byte) (s1 >> 3);
        result[4] = (byte) (s1 >> 11);
        result[5] = (byte) ((s1 >> 19) | (s2 << 2));
        result[6] = (byte) (s2 >> 6);
        result[7] = (byte) ((s2 >> 14) | (s3 << 7));
        result[8] = (byte) (s3 >> 1);
        result[9] = (byte) (s3 >> 9);
        result[10] = (byte) ((s3 >> 17) | (s4 << 4));
        result[11] = (byte) (s4 >> 4);
        result[12] = (byte) (s4 >> 12);
        result[13] = (byte) ((s4 >> 20) | (s5 << 1));
        result[14] = (byte) (s5 >> 7);
        result[15] = (byte) ((s5 >> 15) | (s6 << 6));
        result[16] = (byte) (s6 >> 2);
        result[17] = (byte) (s6 >> 10);
        result[18] = (byte) ((s6 >> 18) | (s7 << 3));
        result[19] = (byte) (s7 >> 5);
        result[20] = (byte) (s7 >> 13);
        result[21] = (byte) s8;
        result[22] = (byte) (s8 >> 8);
        result[23] = (byte) ((s8 >> 16) | (s9 << 5));
        result[24] = (byte) (s9 >> 3);
        result[25] = (byte) (s9 >> 11);
        result[26] = (byte) ((s9 >> 19) | (s10 << 2));
        result[27] = (byte) (s10 >> 6);
        result[28] = (byte) ((s10 >> 14) | (s11 << 7));
        result[29] = (byte) (s11 >> 1);
        result[30] = (byte) (s11 >> 9);
        result[31] = (byte) (s11 >> 17);
        return result;
    }
}
