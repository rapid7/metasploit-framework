# RC4

RC4 is a pure Ruby implementation of the Rc4 algorithm.


## Usage

First require the gem:

    require 'rc4' 

To encrypt:

    key = "nuff rspec"
    enc = RC4.new(key)
    encrypted = enc.encrypt("super-cool-test")

To decrypt:

    dec = RC4.new(key)
    decrypted = dec.decrypt(encrypted)

Since encrypt method is used for encryption and decryption, decrypt is
just an alias to encrypt in order to make the usage more intuitive.

# Note

The original algorithm implementation in Ruby by Max Prokopiev
<max-prokopiev@yandex.ru>.

Aleksandar Simic then modified it to include a test suite and gem
packaged it using gem-this.
<asimic@gmail.com>


I switched the project to use rspec2 and am the now the project's primary maintainer.

Caige Nichols <caigesn@gmail.com>

# License

Ruby-RC4 is released under the MIT license.

# Contributors

(Please let me know if I missed anyone)

- [caiges](http://github.com/caiges)
- [juggler](http://github.com/juggler) (original author)
- Alexandar Simic
