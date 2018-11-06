# Change Log

## [0.6.2](https://github.com/WinRb/rubyntlm/tree/0.6.2) (2017-04-06)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.6.1...0.6.2)

**Merged pull requests:**

- Support Ruby 2.4 [\#34](https://github.com/WinRb/rubyntlm/pull/34) ([fwininger](https://github.com/fwininger))
- ignore pkg directory in git [\#33](https://github.com/WinRb/rubyntlm/pull/33) ([mwrock](https://github.com/mwrock))

## [v0.6.1](https://github.com/WinRb/rubyntlm/tree/v0.6.1) (2016-09-15)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.6.0...v0.6.1)

**Merged pull requests:**

- Release 0.6.1 [\#32](https://github.com/WinRb/rubyntlm/pull/32) ([mwrock](https://github.com/mwrock))
- only test supported rubies and do not test twice [\#31](https://github.com/WinRb/rubyntlm/pull/31) ([mwrock](https://github.com/mwrock))
- Protect against mutating frozen strings [\#30](https://github.com/WinRb/rubyntlm/pull/30) ([mwrock](https://github.com/mwrock))

## [v0.6.0](https://github.com/WinRb/rubyntlm/tree/v0.6.0) (2016-02-16)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/0.5.3...v0.6.0)

**Closed issues:**

- support Extended Protection for Authentication \(Channel Binding Tokens\) [\#27](https://github.com/WinRb/rubyntlm/issues/27)
- RubyNTLM is not documented [\#20](https://github.com/WinRb/rubyntlm/issues/20)

**Merged pull requests:**

- Support Extended Protection for Authentication \(Channel binding\) [\#28](https://github.com/WinRb/rubyntlm/pull/28) ([mwrock](https://github.com/mwrock))

## [0.5.3](https://github.com/WinRb/rubyntlm/tree/0.5.3) (2016-01-22)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.5.3...0.5.3)

## [v0.5.3](https://github.com/WinRb/rubyntlm/tree/v0.5.3) (2016-01-22)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/0.5.2...v0.5.3)

**Merged pull requests:**

- fix session.workstation when passing only domain [\#26](https://github.com/WinRb/rubyntlm/pull/26) ([mwrock](https://github.com/mwrock))

## [0.5.2](https://github.com/WinRb/rubyntlm/tree/0.5.2) (2015-07-20)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/0.5.1...0.5.2)

**Merged pull requests:**

- Add Pass the Hash capability to the NTLM client [\#24](https://github.com/WinRb/rubyntlm/pull/24) ([dmaloney-r7](https://github.com/dmaloney-r7))

## [0.5.1](https://github.com/WinRb/rubyntlm/tree/0.5.1) (2015-06-23)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/0.5.0...0.5.1)

**Merged pull requests:**

- fix NTLM1 auth - NTLM::lm\_response\(pwd, chal\) and NTLM::ntlm\_response… [\#23](https://github.com/WinRb/rubyntlm/pull/23) ([marek-veber](https://github.com/marek-veber))
- Make the session key available to clients [\#21](https://github.com/WinRb/rubyntlm/pull/21) ([jlee-r7](https://github.com/jlee-r7))

## [0.5.0](https://github.com/WinRb/rubyntlm/tree/0.5.0) (2015-02-22)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.4.0...0.5.0)

**Closed issues:**

- require 'net/ntlm/version' in spec/lib/net/ntlm/version\_spec.rb [\#12](https://github.com/WinRb/rubyntlm/issues/12)
- License missing from gemspec [\#5](https://github.com/WinRb/rubyntlm/issues/5)

**Merged pull requests:**

- Encode client and domain in oem/unicode in `Client\#authenticate!` [\#19](https://github.com/WinRb/rubyntlm/pull/19) ([jlee-r7](https://github.com/jlee-r7))
- require version to fix specs [\#17](https://github.com/WinRb/rubyntlm/pull/17) ([sneal](https://github.com/sneal))
- Initial go at an NTLM Client that will do session signing/sealing [\#16](https://github.com/WinRb/rubyntlm/pull/16) ([zenchild](https://github.com/zenchild))
- Verify passwords in Type3 messages [\#15](https://github.com/WinRb/rubyntlm/pull/15) ([jlee-r7](https://github.com/jlee-r7))
- RSpect should =\> expect modernization [\#14](https://github.com/WinRb/rubyntlm/pull/14) ([zenchild](https://github.com/zenchild))
- update http example with EncodeUtil class [\#11](https://github.com/WinRb/rubyntlm/pull/11) ([stensonb](https://github.com/stensonb))
- update readme with how to use and the correct namespacing for using the gem [\#10](https://github.com/WinRb/rubyntlm/pull/10) ([stensonb](https://github.com/stensonb))

## [v0.4.0](https://github.com/WinRb/rubyntlm/tree/v0.4.0) (2013-09-12)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.3.4...v0.4.0)

**Closed issues:**

- The domain should always be capitalized otherwise domain authentication fails [\#7](https://github.com/WinRb/rubyntlm/issues/7)

**Merged pull requests:**

- Add licensing information and clean up attributions to provide licensing... [\#9](https://github.com/WinRb/rubyntlm/pull/9) ([pmorton](https://github.com/pmorton))
- Upcase the domain [\#8](https://github.com/WinRb/rubyntlm/pull/8) ([pmorton](https://github.com/pmorton))
- Refactor/refactor classes [\#6](https://github.com/WinRb/rubyntlm/pull/6) ([dmaloney-r7](https://github.com/dmaloney-r7))

## [v0.3.4](https://github.com/WinRb/rubyntlm/tree/v0.3.4) (2013-08-08)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.3.3...v0.3.4)

## [v0.3.3](https://github.com/WinRb/rubyntlm/tree/v0.3.3) (2013-07-23)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.3.2...v0.3.3)

**Merged pull requests:**

- Typo in NTLM namespace calls [\#4](https://github.com/WinRb/rubyntlm/pull/4) ([dmaloney-r7](https://github.com/dmaloney-r7))

## [v0.3.2](https://github.com/WinRb/rubyntlm/tree/v0.3.2) (2013-06-24)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.3.1...v0.3.2)

**Closed issues:**

- Gem is locked at 1.9.2 [\#1](https://github.com/WinRb/rubyntlm/issues/1)

## [v0.3.1](https://github.com/WinRb/rubyntlm/tree/v0.3.1) (2013-03-29)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.3.0...v0.3.1)

**Merged pull requests:**

- Fix gemspec for the proper ruby version and bump the version [\#2](https://github.com/WinRb/rubyntlm/pull/2) ([pmorton](https://github.com/pmorton))

## [v0.3.0](https://github.com/WinRb/rubyntlm/tree/v0.3.0) (2013-03-25)
[Full Changelog](https://github.com/WinRb/rubyntlm/compare/v0.2.0...v0.3.0)

## [v0.2.0](https://github.com/WinRb/rubyntlm/tree/v0.2.0) (2013-03-22)


\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*