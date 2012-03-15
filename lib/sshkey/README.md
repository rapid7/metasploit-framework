sshkey
======

Generate private and public SSH keys (RSA and DSA supported) using pure Ruby.

	gem install sshkey

Tested on the following Rubies: MRI 1.8.7, 1.9.2, 1.9.3, REE.  Ruby must be compiled with OpenSSL support.

[![Build Status](https://secure.travis-ci.org/bensie/sshkey.png)](http://travis-ci.org/bensie/sshkey)

Usage
-----

When generating a new keypair the default key type is 2048-bit RSA, but you can supply the `type` (RSA or DSA) and `bits` in the options.
You can also (optionally) supply a `comment`:

``` ruby
k = SSHKey.generate

k = SSHKey.generate(:type => "DSA", :bits => 1024, :comment => "foo@bar.com")
```

Return an SSHKey object from an existing RSA or DSA private key (provided as a string)

``` ruby
k = SSHKey.new(File.read("~/.ssh/id_rsa"), :comment => "foo@bar.com")
```

Both of these will return an SSHKey object with the following methods:

``` ruby
# Returns an OpenSSL::PKey::RSA or OpenSSL::PKey::DSA key object
# http://www.ruby-doc.org/stdlib/libdoc/openssl/rdoc/classes/OpenSSL/PKey/RSA.html
# http://www.ruby-doc.org/stdlib/libdoc/openssl/rdoc/classes/OpenSSL/PKey/DSA.html
k.key_object
# => -----BEGIN RSA PRIVATE KEY-----\nMIIEowI...

# Returns the Private Key as a string
k.private_key
# => "-----BEGIN RSA PRIVATE KEY-----\nMIIEowI..."

# Returns the Public Key as a string
k.public_key
# => "-----BEGIN RSA PUBLIC KEY-----\nMIIBCg..."

# Returns the SSH Public Key as a string
k.ssh_public_key
# => "ssh-rsa AAAAB3NzaC1yc2EA...."

# Returns the comment as a string
k.comment
# => "foo@bar.com"

# Returns the MD5 fingerprint as a string
k.md5_fingerprint
# => "2a:89:84:c9:29:05:d1:f8:49:79:1c:ba:73:99:eb:af"

# Returns the SHA1 fingerprint as a string
k.sha1_fingerprint
# => "e4:f9:79:f2:fe:d6:be:2d:ef:2e:c2:fa:aa:f8:b0:17:34:fe:0d:c0"

# Validates SSH Public Key
SSHKey.valid_ssh_public_key? "ssh-rsa AAAAB3NzaC1yc2EA...."
# => true
```

Copyright
---------

Copyright (c) 2011 James Miller
