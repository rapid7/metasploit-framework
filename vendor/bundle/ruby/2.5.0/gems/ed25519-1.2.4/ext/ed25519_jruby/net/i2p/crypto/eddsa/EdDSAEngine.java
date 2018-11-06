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
package net.i2p.crypto.eddsa;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.ScalarOps;
import sun.security.x509.X509Key;

/**
 * Signing and verification for EdDSA.
 *<p>
 * The EdDSA sign and verify algorithms do not interact well with
 * the Java Signature API, as one or more update() methods must be
 * called before sign() or verify(). Using the standard API,
 * this implementation must copy and buffer all data passed in
 * via update().
 *</p><p>
 * This implementation offers two ways to avoid this copying,
 * but only if all data to be signed or verified is available
 * in a single byte array.
 *</p><p>
 *Option 1:
 *</p><ol>
 *<li>Call initSign() or initVerify() as usual.
 *</li><li>Call setParameter(ONE_SHOT_MODE)
 *</li><li>Call update(byte[]) or update(byte[], int, int) exactly once
 *</li><li>Call sign() or verify() as usual.
 *</li><li>If doing additional one-shot signs or verifies with this object, you must
 *         call setParameter(ONE_SHOT_MODE) each time
 *</li></ol>
 *
 *<p>
 *Option 2:
 *</p><ol>
 *<li>Call initSign() or initVerify() as usual.
 *</li><li>Call one of the signOneShot() or verifyOneShot() methods.
 *</li><li>If doing additional one-shot signs or verifies with this object,
 *         just call signOneShot() or verifyOneShot() again.
 *</li></ol>
 *
 * @author str4d
 *
 */
public final class EdDSAEngine extends Signature {
    public static final String SIGNATURE_ALGORITHM = "NONEwithEdDSA";

    private MessageDigest digest;
    private ByteArrayOutputStream baos;
    private EdDSAKey key;
    private boolean oneShotMode;
    private byte[] oneShotBytes;
    private int oneShotOffset;
    private int oneShotLength;

    /**
     *  To efficiently sign or verify data in one shot, pass this to setParameters()
     *  after initSign() or initVerify() but BEFORE THE FIRST AND ONLY
     *  update(data) or update(data, off, len). The data reference will be saved
     *  and then used in sign() or verify() without copying the data.
     *  Violate these rules and you will get a SignatureException.
     */
    public static final AlgorithmParameterSpec ONE_SHOT_MODE = new OneShotSpec();

    private static class OneShotSpec implements AlgorithmParameterSpec {}

    /**
     * No specific EdDSA-internal hash requested, allows any EdDSA key.
     */
    public EdDSAEngine() {
        super(SIGNATURE_ALGORITHM);
    }

    /**
     * Specific EdDSA-internal hash requested, only matching keys will be allowed.
     * @param digest the hash algorithm that keys must have to sign or verify.
     */
    public EdDSAEngine(MessageDigest digest) {
        this();
        this.digest = digest;
    }

    private void reset() {
        if (digest != null)
            digest.reset();
        if (baos != null)
            baos.reset();
        oneShotMode = false;
        oneShotBytes = null;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        reset();
        if (privateKey instanceof EdDSAPrivateKey) {
            EdDSAPrivateKey privKey = (EdDSAPrivateKey) privateKey;
            key = privKey;

            if (digest == null) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key.getParams().getHashAlgorithm());
                } catch (NoSuchAlgorithmException e) {
                    throw new InvalidKeyException("cannot get required digest " + key.getParams().getHashAlgorithm() + " for private key.");
                }
            } else if (!key.getParams().getHashAlgorithm().equals(digest.getAlgorithm()))
                throw new InvalidKeyException("Key hash algorithm does not match chosen digest");
            digestInitSign(privKey);
        } else {
            throw new InvalidKeyException("cannot identify EdDSA private key: " + privateKey.getClass());
        }
    }

    private void digestInitSign(EdDSAPrivateKey privKey) {
        // Preparing for hash
        // r = H(h_b,...,h_2b-1,M)
        int b = privKey.getParams().getCurve().getField().getb();
        digest.update(privKey.getH(), b/8, b/4 - b/8);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        if (publicKey instanceof EdDSAPublicKey) {
            key = (EdDSAPublicKey) publicKey;

            if (digest == null) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key.getParams().getHashAlgorithm());
                } catch (NoSuchAlgorithmException e) {
                    throw new InvalidKeyException("cannot get required digest " + key.getParams().getHashAlgorithm() + " for private key.");
                }
            } else if (!key.getParams().getHashAlgorithm().equals(digest.getAlgorithm()))
                throw new InvalidKeyException("Key hash algorithm does not match chosen digest");
        } else if (publicKey instanceof X509Key) {
            // X509Certificate will sometimes contain an X509Key rather than the EdDSAPublicKey itself; the contained
            // key is valid but needs to be instanced as an EdDSAPublicKey before it can be used.
            EdDSAPublicKey parsedPublicKey;
            try {
                parsedPublicKey = new EdDSAPublicKey(new X509EncodedKeySpec(publicKey.getEncoded()));
            } catch (InvalidKeySpecException ex) {
                throw new InvalidKeyException("cannot handle X.509 EdDSA public key: " + publicKey.getAlgorithm());
            }
            engineInitVerify(parsedPublicKey);
        } else {
            throw new InvalidKeyException("cannot identify EdDSA public key: " + publicKey.getClass());
        }
    }

    /**
     * @throws SignatureException if in one-shot mode
     */
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (oneShotMode)
            throw new SignatureException("unsupported in one-shot mode");
        if (baos == null)
            baos = new ByteArrayOutputStream(256);
        baos.write(b);
    }

    /**
     * @throws SignatureException if one-shot rules are violated
     */
    @Override
    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        if (oneShotMode) {
            if (oneShotBytes != null)
                throw new SignatureException("update() already called");
            oneShotBytes = b;
            oneShotOffset = off;
            oneShotLength = len;
        } else {
            if (baos == null)
                baos = new ByteArrayOutputStream(256);
            baos.write(b, off, len);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            return x_engineSign();
        } finally {
            reset();
            // must leave the object ready to sign again with
            // the same key, as required by the API
            EdDSAPrivateKey privKey = (EdDSAPrivateKey) key;
            digestInitSign(privKey);
        }
    }

    private byte[] x_engineSign() throws SignatureException {
        Curve curve = key.getParams().getCurve();
        ScalarOps sc = key.getParams().getScalarOps();
        byte[] a = ((EdDSAPrivateKey) key).geta();

        byte[] message;
        int offset, length;
        if (oneShotMode) {
            if (oneShotBytes == null)
                throw new SignatureException("update() not called first");
            message = oneShotBytes;
            offset = oneShotOffset;
            length = oneShotLength;
        } else {
            if (baos == null)
                message = new byte[0];
            else
                message = baos.toByteArray();
            offset = 0;
            length = message.length;
        }
        // r = H(h_b,...,h_2b-1,M)
        digest.update(message, offset, length);
        byte[] r = digest.digest();

        // r mod l
        // Reduces r from 64 bytes to 32 bytes
        r = sc.reduce(r);

        // R = rB
        GroupElement R = key.getParams().getB().scalarMultiply(r);
        byte[] Rbyte = R.toByteArray();

        // S = (r + H(Rbar,Abar,M)*a) mod l
        digest.update(Rbyte);
        digest.update(((EdDSAPrivateKey) key).getAbyte());
        digest.update(message, offset, length);
        byte[] h = digest.digest();
        h = sc.reduce(h);
        byte[] S = sc.multiplyAndAdd(h, a, r);

        // R+S
        int b = curve.getField().getb();
        ByteBuffer out = ByteBuffer.allocate(b/4);
        out.put(Rbyte).put(S);
        return out.array();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            return x_engineVerify(sigBytes);
        } finally {
            reset();
        }
    }

    private boolean x_engineVerify(byte[] sigBytes) throws SignatureException {
        Curve curve = key.getParams().getCurve();
        int b = curve.getField().getb();
        if (sigBytes.length != b/4)
            throw new SignatureException("signature length is wrong");

        // R is first b/8 bytes of sigBytes, S is second b/8 bytes
        digest.update(sigBytes, 0, b/8);
        digest.update(((EdDSAPublicKey) key).getAbyte());
        // h = H(Rbar,Abar,M)
        byte[] message;
        int offset, length;
        if (oneShotMode) {
            if (oneShotBytes == null)
                throw new SignatureException("update() not called first");
            message = oneShotBytes;
            offset = oneShotOffset;
            length = oneShotLength;
        } else {
            if (baos == null)
                message = new byte[0];
            else
                message = baos.toByteArray();
            offset = 0;
            length = message.length;
        }
        digest.update(message, offset, length);
        byte[] h = digest.digest();

        // h mod l
        h = key.getParams().getScalarOps().reduce(h);

        byte[] Sbyte = Arrays.copyOfRange(sigBytes, b/8, b/4);
        // R = SB - H(Rbar,Abar,M)A
        GroupElement R = key.getParams().getB().doubleScalarMultiplyVariableTime(
                ((EdDSAPublicKey) key).getNegativeA(), h, Sbyte);

        // Variable time. This should be okay, because there are no secret
        // values used anywhere in verification.
        byte[] Rcalc = R.toByteArray();
        for (int i = 0; i < Rcalc.length; i++) {
            if (Rcalc[i] != sigBytes[i])
                return false;
        }
        return true;
    }

    /**
     *  To efficiently sign all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data)
     *  sig = sign()
     *</pre>
     *
     * @param data the message to be signed
     * @return the signature
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public byte[] signOneShot(byte[] data) throws SignatureException {
        return signOneShot(data, 0, data.length);
    }

    /**
     *  To efficiently sign all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data, off, len)
     *  sig = sign()
     *</pre>
     *
     * @param data byte array containing the message to be signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @return the signature
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public byte[] signOneShot(byte[] data, int off, int len) throws SignatureException {
        oneShotMode = true;
        update(data, off, len);
        return sign();
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data)
     *  ok = verify(signature)
     *</pre>
     *
     * @param data the message that was signed
     * @param signature of the message
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(byte[] data, byte[] signature) throws SignatureException {
        return verifyOneShot(data, 0, data.length, signature, 0, signature.length);
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data, off, len)
     *  ok = verify(signature)
     *</pre>
     *
     * @param data byte array containing the message that was signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @param signature of the message
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(byte[] data, int off, int len, byte[] signature) throws SignatureException {
        return verifyOneShot(data, off, len, signature, 0, signature.length);
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data)
     *  ok = verify(signature, sigoff, siglen)
     *</pre>
     *
     * @param data the message that was signed
     * @param signature byte array containing the signature
     * @param sigoff the start of the signature
     * @param siglen the length of the signature
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(byte[] data, byte[] signature, int sigoff, int siglen) throws SignatureException {
        return verifyOneShot(data, 0, data.length, signature, sigoff, siglen);
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data, off, len)
     *  ok = verify(signature, sigoff, siglen)
     *</pre>
     *
     * @param data byte array containing the message that was signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @param signature byte array containing the signature
     * @param sigoff the start of the signature
     * @param siglen the length of the signature
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(byte[] data, int off, int len, byte[] signature, int sigoff, int siglen) throws SignatureException {
        oneShotMode = true;
        update(data, off, len);
        return verify(signature, sigoff, siglen);
    }

    /**
     * @throws InvalidAlgorithmParameterException if spec is ONE_SHOT_MODE and update() already called
     * @see #ONE_SHOT_MODE
     */
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
        if (spec.equals(ONE_SHOT_MODE)) {
            if (oneShotBytes != null || (baos != null && baos.size() > 0))
                throw new InvalidAlgorithmParameterException("update() already called");
            oneShotMode = true;
        } else {
            super.engineSetParameter(spec);
        }
    }

    /**
     * @deprecated
     */
    @Override
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    @Override
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
}
