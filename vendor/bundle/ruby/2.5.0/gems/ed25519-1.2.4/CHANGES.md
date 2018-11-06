## [1.2.4] (2018-01-04)

[1.2.4]: https://github.com/crypto-rb/ed25519/compare/v1.2.3...v1.2.4

* Fix JRuby platform name
* Add license information to gemspec

## [1.2.3] (2017-12-31)

[1.2.3]: https://github.com/crypto-rb/ed25519/compare/v1.2.2...v1.2.3

* [#18](https://github.com/crypto-rb/ed25519/pull/18)
  `ext/ed25519_ref10`: Consolidate fe.c and ge.c

## [1.2.2] (2017-12-31)

[1.2.2]: https://github.com/crypto-rb/ed25519/compare/v1.2.1...v1.2.2

* [#17](https://github.com/crypto-rb/ed25519/pull/17)
  Test against Ruby 2.5.0

* [#16](https://github.com/crypto-rb/ed25519/pull/16)
  Move project to the crypto-rb GitHub organization

## [1.2.1] (2017-12-15)

[1.2.1]: https://github.com/crypto-rb/ed25519/compare/v1.2.0...v1.2.1

* [#14](https://github.com/crypto-rb/ed25519/pull/14)
  Support MRI 2.0+

## [1.2.0] (2017-12-15)

[1.2.0]: https://github.com/crypto-rb/ed25519/compare/v1.1.0...v1.2.0

* [#13](https://github.com/crypto-rb/ed25519/pull/13)
  Add `Ed25519::SigningKey.from_keypair`

* [#12](https://github.com/crypto-rb/ed25519/pull/12)
  Add `Ed25519.validate_key_bytes` method

## [1.1.0] (2017-12-13)

[1.1.0]: https://github.com/crypto-rb/ed25519/compare/v1.0.0...v1.1.0

* [#11](https://github.com/crypto-rb/ed25519/pull/11)
  ext/ed25519_java: switch to str4d/ed25519-java implementation (fixes #4)

* [#9](https://github.com/crypto-rb/ed25519/pull/9)
  Implement Java backend as a proper JRuby extension

* [#8](https://github.com/crypto-rb/ed25519/pull/8)
  Use an attr_accessor for Ed25519.provider

## [1.0.0] (2017-12-12)

[1.0.0]: https://github.com/crypto-rb/ed25519/compare/v0.1.0...v1.0.0

* [#7](https://github.com/crypto-rb/ed25519/pull/7)
  Keypair refactor

* [#6](https://github.com/crypto-rb/ed25519/pull/6)
  Switch from "ref" C implementation to SUPERCOP "ref10"

* [#5](https://github.com/crypto-rb/ed25519/pull/5)
  Raise Ed25519::VerifyError if signature verification fails

# 0.1.0 (2017-12-11)

* Initial release
