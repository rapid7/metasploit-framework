# ed25519.rb [![Latest Version][gem-shield]][gem-link] [![Build Status][build-image]][build-link] [![Appveyor CI Status][appveyor-image]][appveyor-link] [![Yard Docs][docs-image]][docs-link] [![License: MIT][license-image]][license-link] [![Gitter Chat][gitter-image]][gitter-link]

[gem-shield]: https://badge.fury.io/rb/ed25519.svg
[gem-link]: https://rubygems.org/gems/ed25519
[build-image]: https://travis-ci.org/crypto-rb/ed25519.svg?branch=master
[build-link]: https://travis-ci.org/crypto-rb/ed25519
[appveyor-image]: https://ci.appveyor.com/api/projects/status/4s05bcae0mow85v1?svg=true
[appveyor-link]: https://ci.appveyor.com/project/tarcieri/ed25519
[docs-image]: https://img.shields.io/badge/yard-docs-blue.svg
[docs-link]: http://www.rubydoc.info/gems/ed25519/1.2.3
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/crypto-rb/ed25519/blob/master/LICENSE
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/crypto-rb/Lobby

A Ruby binding to the Ed25519 elliptic curve public-key signature system
described in [RFC 8032].

Two implementations are provided: a MRI C extension which uses the "ref10"
implementation from the SUPERCOP benchmark suite, and a pure Java version
based on [str4d/ed25519-java].

Ed25519 is one of two notable algorithms implemented atop the Curve25519
elliptic curve. The [x25519 gem] is a related project of this one,
and implements the X25519 Diffie-Hellman key exchange algorithm on the
Montgomery form of Curve25519.

[RFC 8032]: https://tools.ietf.org/html/rfc8032
[str4d/ed25519-java]: https://github.com/str4d/ed25519-java
[x25519 gem]: https://github.com/crypto-rb/x25519

## What is Ed25519?

Ed25519 is a modern implementation of a [Schnorr signature] system using
elliptic curve groups.

Ed25519 provides a 128-bit security level, that is to say, all known attacks
take at least 2^128 operations, providing the same security level as AES-128,
NIST P-256, and RSA-3072.

![Ed25519 Diagram](https://raw.github.com/crypto-rb/ed25519/master/ed25519.png)

Ed25519 has a number of unique properties that make it one of the best-in-class
digital signature algorithms:

* ***Small keys***: Ed25519 keys are only 256-bits (32 bytes), making them
  small enough to easily copy around. Ed25519 also allows the public key
  to be derived from the private key, meaning that it doesn't need to be
  included in a serialized private key in cases you want both.
* ***Small signatures***: Ed25519 signatures are only 512-bits (64 bytes),
  one of the smallest signature sizes available.
* ***Deterministic***: Unlike (EC)DSA, Ed25519 does not rely on an entropy
  source when signing messages. This can be a potential attack vector if
  the entropy source is not generating good random numbers. Ed25519 avoids
  this problem entirely and will always generate the same signature for the
  same data.
* ***Collision Resistant***: Hash-function collisions do not break this
  system. This adds a layer of defense against the possibility of weakness
  in the selected hash function.

You can read more on [Dan Bernstein's Ed25519 site](http://ed25519.cr.yp.to/).

[Schnorr signature]: https://en.wikipedia.org/wiki/Schnorr_signature

## Requirements

**ed25519.rb** is supported on and tested against the following platforms:

* MRI 2.0, 2.1, 2.2, 2.3, 2.4, 2.5
* JRuby 9000+

## Installation

Add this line to your application's Gemfile:

    gem 'ed25519'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ed25519

# Usage

Require **ed25519.rb** in your Ruby program:

```ruby
require "ed25519"
```

Generate a new random signing key:

```ruby
signing_key = Ed25519::SigningKey.generate
```

Sign a message with the signing key:

```ruby
signature = signing_key.sign(message)
```

Obtain the verify key for a given signing key:

```ruby
verify_key = signing_key.verify_key
```

Check the validity of a signature:

```ruby
verify_key.verify(signature, message)
```

The verify method will return `true` if the signature verifies, or raise
`Ed25519::VerifyError` if verification fails.

### Serializing Keys

Keys can be serialized as 32-byte binary strings as follows:

```ruby
signature_key_bytes = signing_key.to_bytes
verify_key_bytes = verify_key.to_bytes
```

The binary serialization can be passed directly into the constructor for a given key type:

```ruby
signing_key = Ed25519::SigningKey.new(signature_key_bytes)
verify_key  = Ed25519::VerifyKey.new(verify_key_bytes)
```

## Security Notes

The Ed25519 "ref10" implementation from SUPERCOP was lovingly crafted by expert
security boffins with great care taken to prevent timing attacks. The same
cannot be said for the C code used in the **ed25519.rb** C extension or in the
entirety of the provided Java implementation.

Care should be taken to avoid leaking to the attacker how long it takes to
generate keys or sign messages (at least until **ed25519.rb** itself can be audited
by experts who can fix any potential timing vulnerabilities)

**ed25519.rb** relies on a strong `SecureRandom` for key generation.
Weaknesses in the random number source can potentially result in insecure keys.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/crypto-rb/ed25519.
This project is intended to be a safe, welcoming space for collaboration,
and contributors areexpected to adhere to the [Contributor Covenant](http://contributor-covenant.org)
code of conduct.

## License

Copyright (c) 2012-2018 Tony Arcieri. Distributed under the MIT License. See
[LICENSE] for further details.

[LICENSE]: https://github.com/crypto-rb/ed25519/blob/master/LICENSE

## Code of Conduct

Everyone interacting in the **ed25519.rb** project’s codebases, issue trackers, chat
rooms and mailing lists is expected to follow the [code of conduct].

[code of conduct]: https://github.com/crypto-rb/ed25519/blob/master/CODE_OF_CONDUCT.md
