package org.cryptorb;

import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.jruby.Ruby;
import org.jruby.RubyModule;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

@JRubyModule(name="Ed25519::Provider::JRuby")
public class Ed25519Provider {
	public static RubyModule createEd25519Module(Ruby runtime) {
		RubyModule mEd25519 = runtime.defineModule("Ed25519");
		RubyModule mEd25519Provider = mEd25519.defineModuleUnder("Provider");
		RubyModule mEd25519ProviderJRuby = mEd25519Provider.defineOrGetModuleUnder("JRuby");
		mEd25519ProviderJRuby.defineAnnotatedMethods(Ed25519Provider.class);

		return mEd25519ProviderJRuby;
	}

	@JRubyMethod(name = "create_keypair", module = true)
	public static IRubyObject create_keypair(ThreadContext context, IRubyObject self, IRubyObject seed) {
		byte[] seedBytes = seed.convertToString().getByteList().bytes();

		if (seedBytes.length != 32) {
			throw context.runtime.newArgumentError("expected 32-byte seed value, got " + seedBytes.length);
		}

		EdDSAParameterSpec edParams = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
                EdDSAPrivateKeySpec signingKey = new EdDSAPrivateKeySpec(seedBytes, edParams);
                EdDSAPublicKeySpec verifyKey = new EdDSAPublicKeySpec(signingKey.getA(), edParams);

		byte[] keypair = new byte[64];

		System.arraycopy(seedBytes, 0, keypair, 0, 32);
		System.arraycopy(verifyKey.getA().toByteArray(), 0, keypair, 32, 32);

		return RubyString.newString(context.getRuntime(), keypair);
	}

	@JRubyMethod(name = "sign", module = true)
	public static IRubyObject sign(ThreadContext context, IRubyObject self, IRubyObject keypair, IRubyObject msg) throws Exception {
		byte[] keypairBytes = keypair.convertToString().getByteList().bytes();

		if (keypairBytes.length != 64) {
			throw context.runtime.newArgumentError("expected 64-byte keypair value, got " + keypairBytes.length);
		}

                EdDSAParameterSpec edParams = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
                Signature signer = new EdDSAEngine(MessageDigest.getInstance(edParams.getHashAlgorithm()));

		byte[] seedBytes = Arrays.copyOfRange(keypairBytes, 0, 32);
		EdDSAPrivateKeySpec signingKey = new EdDSAPrivateKeySpec(seedBytes, edParams);

                signer.initSign(new EdDSAPrivateKey(signingKey));
                signer.update(msg.convertToString().getByteList().bytes());

		return RubyString.newString(context.getRuntime(), signer.sign());
	}

	@JRubyMethod(name = "verify", module = true)
	public static IRubyObject verify(ThreadContext context, IRubyObject self, IRubyObject verify_key, IRubyObject signature, IRubyObject msg) throws Exception {
		byte[] verifyKeyBytes = verify_key.convertToString().getByteList().bytes();
		byte[] signatureBytes = signature.convertToString().getByteList().bytes();

		if (verifyKeyBytes.length != 32) {
			throw context.runtime.newArgumentError("expected 32-byte verify key, got " + verifyKeyBytes.length);
		}

		if (signatureBytes.length != 64) {
			throw context.runtime.newArgumentError("expected 64-byte signature, got " + signatureBytes.length);
		}

		EdDSAParameterSpec edParams = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
		Signature signer = new EdDSAEngine(MessageDigest.getInstance(edParams.getHashAlgorithm()));
		EdDSAPublicKeySpec verifyKey = new EdDSAPublicKeySpec(verifyKeyBytes, edParams);

		signer.initVerify(new EdDSAPublicKey(verifyKey));
		signer.update(msg.convertToString().getByteList().bytes());

		boolean isValid = signer.verify(signatureBytes);
		return context.runtime.newBoolean(isValid);
	}
}
