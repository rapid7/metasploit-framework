## 1.0.5 (2017-02-25)

* [#19](https://github.com/cryptosphere/sysrandom/pull/19)
  Replace Fixnum references with Integer.
  ([@tarcieri])

## 1.0.4 (2016-12-04)

* [#15](https://github.com/cryptosphere/sysrandom/pull/16)
  Argument handling fixups.
  ([@tarcieri])

## 1.0.3 (2016-09-27)

* [#14](https://github.com/cryptosphere/sysrandom/pull/14)
  Return empty string on `random_bytes(0)` as SecureRandom does.
  ([@grempe])

## 1.0.2 (2016-06-06)

* [#12](https://github.com/cryptosphere/sysrandom/pull/12)
  Remove unnecessary SecureRandom reference in 'hex' method.
  ([@tarcieri])

* [#6](https://github.com/cryptosphere/sysrandom/pull/6)
  Raise ArgumentError if 0 random bytes are requested (new minimum is 1).
  ([@azet])

## 1.0.1 (2016-05-29)

* [#11](https://github.com/cryptosphere/sysrandom/pull/11)
  Use NativePRNGNonBlocking for JRuby if available.
  ([@coda])

* [#8](https://github.com/cryptosphere/sysrandom/pull/8)
  Upstream libsodium change: wait for `/dev/random` to be seeded before reading from `/dev/urandom`.
  ([@tarcieri])


## 1.0.0 (2016-05-28)

* Initial release.


[@tarcieri]: https://github.com/tarcieri
[@coda]: https://github.com/coda
[@azet]: https://github.com/azet
[@grempe]: https://github.com/grempe
