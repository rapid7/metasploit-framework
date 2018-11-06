# Sysrandom [![Gem Version][gem-image]][gem-link] [![Build Status][build-image]][build-link] [![ISC licensed][license-image]][license-link]

[gem-image]: https://badge.fury.io/rb/sysrandom.svg
[gem-link]: https://rubygems.org/gems/sysrandom
[build-image]: https://secure.travis-ci.org/cryptosphere/sysrandom.svg?branch=master
[build-link]: https://travis-ci.org/cryptosphere/sysrandom
[license-image]: https://img.shields.io/badge/license-ISC-blue.svg
[license-link]: https://github.com/cryptosphere/sysrandom/blob/master/LICENSE.txt

Secure random number generation for Ruby using system RNG facilities e.g. `/dev/urandom`, `getrandom(2)`

## Why?

System/OS-level random number generators like `/dev/urandom` and `getrandom(2)`
provide the best option for generating cryptographically secure random numbers.

Ruby's built-in SecureRandom does not provide this, but instead uses OpenSSL's
userspace RNG. This has been a [source of vulnerabilities][emboss] in Ruby, and
an [open Ruby bug ticket][bug] contains much discussion on the issue with no
clear path to resolution.

This gem aims to solve the problem.

## Description

In cryptography circles, [the prevailing advice is to use OS RNG functionality][/dev/urandom],
namely `/dev/urandom` or equivalent calls which use an OS-level CSPRNG to
produce random numbers.

This gem provides an easy-to-install repackaging of the `randombytes`
functionality from [libsodium] for the purpose of generating secure random
numbers trustworthy for use in cryptographic contexts, such as generating
cryptographic keys, initialization vectors, or nonces.

The following random number generators are utilized:

| Platform | RNG                                                    |
|----------|--------------------------------------------------------|
| Linux    | [getrandom(2)] if available, otherwise [/dev/urandom]  |
| Windows  | [RtlGenRandom] CryptGenRandom without CryptoAPI deps   |
| OpenBSD  | [arc4random(3)] with ChaCha20 CSPRNG (not RC4)         |
| JRuby    | [NativePRNGNonBlocking] on Java 8, otherwise SHA1PRNG  |
| Others   | [/dev/urandom]                                         |

[emboss]:        https://emboss.github.io/blog/2013/08/21/openssl-prng-is-not-really-fork-safe/
[bug]:           https://bugs.ruby-lang.org/issues/9569
[libsodium]:     https://github.com/jedisct1/libsodium
[getrandom(2)]:  http://man7.org/linux/man-pages/man2/getrandom.2.html
[/dev/urandom]:  http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/
[RtlGenRandom]:  https://msdn.microsoft.com/en-us/library/windows/desktop/aa387694(v=vs.85).aspx
[arc4random(3)]: http://man.openbsd.org/arc4random.3
[NativePRNGNonBlocking]: https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/

## Supported Platforms

Sysrandom is tested on the following Ruby implementations:

* Ruby (MRI) 2.0, 2.1, 2.2, 2.3
* JRuby 9.1.1.0

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'sysrandom'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install sysrandom

## Usage

`Sysrandom` aims to be API-compatible with Ruby's built-in `SecureRandom` class,
but always prefers OS-level RNG wherever it's available:

```ruby
>> Sysrandom.random_number(42)
=> 15
>> Sysrandom.random_bytes(32)
=> "\xD6J\xB3\xD2\x8B\x7F*9D\xB7\xF9\xEA\xE2\\\xAAH\tV#\xEC\x84\xE3E\r\x97\xB9\b\xFCH\x17\xA0\v"
>> Sysrandom.base64(32)
=> "WXPkxfAuLRpnI6Z4zFb4E+MIenx6w6vKhe01+rMPuIQ="
>> Sysrandom.urlsafe_base64(32)
=> "37rsMfR4X8g7Bb-uDJEekRHnB3r_7nO03cv52ilaWqE="
>> Sysrandom.hex(32)
=> "c950496ce200abf7d18eb1414e9206c6335f971a37d0394114f56439b59831ba"
>> Sysrandom.uuid
=> "391c6f52-8017-4838-9790-131a9b979c63"
```

* [SecureRandom API docs](http://ruby-doc.org/stdlib-2.0.0/libdoc/securerandom/rdoc/SecureRandom.html)

## Patching SecureRandom with Sysrandom

Since Sysrandom is SecureRandom-compatible, it can be patched in-place of
SecureRandom if you prefer its RNG behavior.

To do this, require `sysrandom/securerandom`:

```ruby
>> SecureRandom
=> SecureRandom
>> require "sysrandom/securerandom"
=> true
>> SecureRandom
=> Sysrandom
>> SecureRandom.hex(32)
=> "d1bbe8c1ab78fc2fe514c5623d913a27ffd2dcdc9e002f3b358bb01a996962f1"
```

## Contributing

* Fork this repository on Github
* Make your changes and send a pull request
* If your changes look good, we'll merge them

## Copyright

Copyright (c) 2013-2017 Frank Denis, Tony Arcieri. See LICENSE.txt for further details.
