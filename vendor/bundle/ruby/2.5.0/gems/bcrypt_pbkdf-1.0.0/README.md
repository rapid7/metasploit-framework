# bcrypt_pdkfd-ruby

bcrypt_pdkfd is a ruby gem implementing bcrypt_pdkfd from OpenBSD. This is currently used by net-ssh to read password encrypted Ed25519 keys.

[![Build Status](https://travis-ci.org/mfazekas/bcrypt_pbkdf-ruby.png?branch=master)](https://travis-ci.org/mfazekas/bcrypt_pbkdf-ruby)

# Acknowledgements

* The gut of the code is based on OpenBSD's bcrypt_pbkdf.c implementation
* Some ideas/code were taken adopted bcrypt-ruby: https://github.com/codahale/bcrypt-ruby

# Links:

http://www.tedunangst.com/flak/post/bcrypt-pbkdf
http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libutil/bcrypt_pbkdf.c?rev=1.13&content-type=text/x-cvsweb-markup
