# -*- coding: binary -*-

##
#
# RFB protocol support
#
# by Joshua J. Drake <jduck>
#
# Based on:
# vnc_auth_none contributed by Matteo Cantoni <goony[at]nothink.org>
# vnc_auth_login contributed by carstein <carstein.sec[at]gmail.com>
#
##

# Required for VNC authentication
require 'openssl'

module Rex
module Proto
module RFB

##
# A bit of information about the DES algorithm was found here:
# http://www.vidarholen.net/contents/junk/vnc.html
#
# In addition, VNC uses two individual 8 byte block encryptions rather than
# using any block mode (like cbc, ecb, etc).
##

class Cipher

	def self.mangle_password(password)
		key = ''
		key = password.dup if password
		key.slice!(8,key.length) if key.length > 8
		key << "\x00" * (8 - key.length) if key.length < 8

		# We have to mangle the key so the LSB are kept vs the MSB
		[key.unpack('B*').first.scan(/.{8}/).map! { |e| e.reverse }.join].pack('B*')
	end

	def self.encrypt(plain, password)
		key = self.mangle_password(password)

		# pad the plain to 16 chars
		plain << ("\x00" * (16 - plain.length)) if plain.length < 16

		# VNC auth does two 8-byte blocks individually instead supporting some block mode
		cipher = ''
		2.times { |x|
			c = OpenSSL::Cipher::Cipher.new('des')
			c.encrypt
			c.key = key
			cipher << c.update(plain[x*8, 8])
		}

		cipher
	end

	#
	# NOTE: The default password is that of winvnc/etc which is used for
	# encrypting the password(s) on disk/in registry.
	#
	def self.decrypt(cipher, password = "\x17\x52\x6b\x06\x23\x4e\x58\x07")
		key = self.mangle_password(password)

		# pad the cipher text to 9 bytes
		cipher << ("\x00" * (9 - cipher.length)) if cipher.length < 9

		# NOTE: This only does one 8 byte block
		plain = ''
		c = OpenSSL::Cipher::Cipher.new('des')
		c.decrypt
		c.key = key
		c.update(cipher)
	end

end

end
end
end
