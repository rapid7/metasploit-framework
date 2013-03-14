# -*- coding: binary -*-
require 'net/ssh'
require 'test/unit'

# Unit tests for Net::SSH::Utils::Key.fingerprint. Not going
# to mess around with this weird story testing that the rest
# of Net::SSH uses.
#
# By the way, it would be extremely silly to actually use these
# keys for anything. They're passwordless and now quite effectively
# compromised. :)
class Fingerprint < Test::Unit::TestCase

	def test_rsa_private
		rsa_private = <<-EOM
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA/kDqlZOy4FE7+0m5rO/x1YDMxMnsj2SFIAtxF6TAAyxqPt7s
wJtuVhQv8xNvRYjoL2E7JH95gtIRmwOxLReRd0kVyrCi9mf9T7ninSKLb264IUfQ
VdivGdFGJbTxlxp2w9oXLt9jrUXWgYAn5z/4cauOtGQvvAJz4m/G+eJyafuvi83i
rnOP2v7fPtPY1Xzok0PvdOHDw9Vk8rOLAB4quOf0kSP2DMFOr5Kyk2qQvOar2wnd
npxdEaDgKrdnE6hQ1yv/uctEgP7/5UJ8RHrMp/D9DcTRYZMxxnCawt72jxYqgelL
3m/329ER/6StAsVce+sFPDIBsFssLwnJtJjzdwIBIwKCAQEArlhmV/BAJMn9Ppj0
WVQTixZ9yMT5++0oFfk3my8klHY6Ob1vJPzd8eH0/nO6A8uX5fmHo/+jx2t5yWGe
EEqs5BTbvi/6t5fDpGI0/gkPJ9bkqRtNB6qGsp4hePEasMGwhkxnqxzWorOLxoPD
l0HO7twKFUwDeZtIJj4EyJtHJBjumimnG7cpjZi0w84XMQqpUyAcTkXhCICIiMtV
UwAfjsxiB+cyd9B3riWHtyyo8SCqH1qFELOB9goOVI7moXIB0Z6TwUrvBiDC7cDO
Qajj97kpeuQHRFSkqwZHVGkZ0Hy1mm7VTRNOfE590rv4daJDQTG5W2JbETAknbW8
3El+CwKBgQD/iDIgEChLxufEKO4CpKFIHki+PmaFCm6zLILHbD6fV8oPL4iSF5T+
9OmFXgTmscl6C4J3g2+mzuxN9uDiyUE6lVIDiKZzzd7Y+sdbmC1oUkrMviq9Uuc1
lisPMKdfz2Xf6GJU52j6l0hg9FRAkcut0CkvGwZqOPrfBI5OYVtTzwKBgQD+uB8E
QIrSJZhoza6fCVa+28Gymaqr4lXqqV2R0CoIBjPWa2o6W8b2h10cn5neViLkYc4O
uCbuETs9Tdtz9Et+RX1kt0I0H4W1T8Hz4eHCjGLT0bg0IFs2ttxjjHOmb6UXGE//
5qAqz0DkN/5MxW0Ml1lSe+bSqPoXxH0dPKfH2QKBgQCvONHqGbU7RpBL/s8XwVim
eyqRFNiVvgLEAUO78nQVfgbl13OXYKCu09NUIzaPj9qc1LE8AlswjePdsJo1HEn8
SSJLkOcq1k+qupdUwB8i9pmw923Dpo/qOxY2TT+SJ9DUDRA6OEf8SnrGI+IAY/lh
PkggTQu2jXjTcNacJYBz+wKBgQD3cQgwBC8VSRe2RCX5lAsfzingsoiJt0wlyRkR
Td+wBgZ4hZpkk6tV4pT3O/SO11UYXwKvNow3uPe35TuVNnU41cpElMP4Hp8lKOhL
///hj7B1/u10dzQJQ+wI7ta+8By3WXJJC+wMVE2qf4lR5FtOD14VnO7bRRA0WHmK
HapNGwKBgQCx09+WsoCTH6jIkfroT77t+DAMHrzH67AZy+hu1+dBCEyN4Mkw8CD6
sRMIIcy/R5W1mlRFFaYMbtJogjtWwDUjzTEPvIU6tdJhj8GOg1pxPLqD+r/Mwc88
228W9YHRSybK5kK61QmoWHDS13OJCOa+xA59ym1GpE1KyliwpsPajg==
-----END RSA PRIVATE KEY-----
		EOM

		fp = Net::SSH::Utils::Key.fingerprint(:data => rsa_private)
		assert_equal("af:76:e4:f8:37:7b:52:8c:77:61:5b:d3:b0:d3:05:e4",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => rsa_private, 
			:format => :compact
		)
		assert_equal("af76e4f8377b528c77615bd3b0d305e4",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => rsa_private, 
			:format => :bin
		)
		assert_equal("\xaf\x76\xe4\xf8\x37\x7b\x52\x8c\x77\x61\x5b\xd3\xb0\xd3\x05\xe4", fp)

		assert_raise OpenSSL::PKey::PKeyError do
			Net::SSH::Utils::Key.fingerprint(
				:data => rsa_private,
				:public => true
			)
		end
	end

	def test_rsa_public
		rsa_public = <<-EOM
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA/kDqlZOy4FE7+0m5rO/x1YDMxMnsj2SFIAtxF6TAAyxqPt7swJtuVhQv8xNvRYjoL2E7JH95gtIRmwOxLReRd0kVyrCi9mf9T7ninSKLb264IUfQVdivGdFGJbTxlxp2w9oXLt9jrUXWgYAn5z/4cauOtGQvvAJz4m/G+eJyafuvi83irnOP2v7fPtPY1Xzok0PvdOHDw9Vk8rOLAB4quOf0kSP2DMFOr5Kyk2qQvOar2wndnpxdEaDgKrdnE6hQ1yv/uctEgP7/5UJ8RHrMp/D9DcTRYZMxxnCawt72jxYqgelL3m/329ER/6StAsVce+sFPDIBsFssLwnJtJjzdw== user@msf3
		EOM

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => rsa_public,
			:public => true
		)
		assert_equal("af:76:e4:f8:37:7b:52:8c:77:61:5b:d3:b0:d3:05:e4",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => rsa_public, 
			:format => :compact,
			:public => true
		)

		assert_equal("af76e4f8377b528c77615bd3b0d305e4",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => rsa_public, 
			:format => :bin,
			:public => true
		)
		assert_equal("\xaf\x76\xe4\xf8\x37\x7b\x52\x8c\x77\x61\x5b\xd3\xb0\xd3\x05\xe4", fp)

		assert_raise OpenSSL::PKey::PKeyError do
			Net::SSH::Utils::Key.fingerprint(
				:data => rsa_public,
				:public => false
			)
		end
	end

	def test_dsa_private
		dsa_private = <<-EOM
-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQDee7R8F36phQQ5fnBf1HcOctMcWWXX6/2EXdOZMykRXgPpGloK
FaO/Wjo1Lnlot+O0rweu0VlOepNtpBCJu/kDHePci3kH8Uo/AMCUKb+72kZumJPr
N46WU3v4Shck4MUOXKW56/EkMXaHAQxM7wgFSRUbTYeyIxTOG+qH3Cc9KQIVANjT
p28ydND3lmXzw1YVwRSDO5LfAoGAatFZrDKn0DOKiJlPMGF/ES3Ktr+GpltAwrdp
WCgG8grKphnzpnfgcKra3TgMOzipovA362o91RQ9OO0UK2fnrzSpphl6AgAEQZ7m
+qgRWj4hfQZCik2p6rP2F1rgLlZw10OPJE4ECcgHJ5zXZMEzrc4ihGnIs0SF0Lbs
hgdI0N4CgYAjYXbR4tVZb9SrSjRw86n0p/90ec7zgyBZTZVF+ImkstVlnQFh5H3/
Rf35YUjgsppnBo3sRT/aCEQmbBdzFBXwo0XLBkqFdg21ZtuJZCv6NrNr/Mn8zeVI
rtPv0QRjA/92/OQ5T6Gj7m8gqKEshzW5gj17KH3pdOnNaLBkfJVYvQIUHzk1VI9A
2NbDpCiAmhnqoeYeTXU=
-----END DSA PRIVATE KEY-----
		EOM

		fp = Net::SSH::Utils::Key.fingerprint(:data => dsa_private)
		assert_equal("ad:64:88:d8:f6:78:65:d4:da:a9:ba:56:61:74:a5:1c",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => dsa_private, 
			:format => :compact
		)
		assert_equal("ad6488d8f67865d4daa9ba566174a51c",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => dsa_private, 
			:format => :bin
		)
		assert_equal("\xad\x64\x88\xd8\xf6\x78\x65\xd4\xda\xa9\xba\x56\x61\x74\xa5\x1c",fp)

		assert_raise OpenSSL::PKey::PKeyError do
			Net::SSH::Utils::Key.fingerprint(
				:data => dsa_private,
				:public => true
			)
		end
	end

	def test_dsa_public
		dsa_public = <<-EOM
ssh-dss AAAAB3NzaC1kc3MAAACBAN57tHwXfqmFBDl+cF/Udw5y0xxZZdfr/YRd05kzKRFeA+kaWgoVo79aOjUueWi347SvB67RWU56k22kEIm7+QMd49yLeQfxSj8AwJQpv7vaRm6Yk+s3jpZTe/hKFyTgxQ5cpbnr8SQxdocBDEzvCAVJFRtNh7IjFM4b6ofcJz0pAAAAFQDY06dvMnTQ95Zl88NWFcEUgzuS3wAAAIBq0VmsMqfQM4qImU8wYX8RLcq2v4amW0DCt2lYKAbyCsqmGfOmd+BwqtrdOAw7OKmi8Dfraj3VFD047RQrZ+evNKmmGXoCAARBnub6qBFaPiF9BkKKTanqs/YXWuAuVnDXQ48kTgQJyAcnnNdkwTOtziKEacizRIXQtuyGB0jQ3gAAAIAjYXbR4tVZb9SrSjRw86n0p/90ec7zgyBZTZVF+ImkstVlnQFh5H3/Rf35YUjgsppnBo3sRT/aCEQmbBdzFBXwo0XLBkqFdg21ZtuJZCv6NrNr/Mn8zeVIrtPv0QRjA/92/OQ5T6Gj7m8gqKEshzW5gj17KH3pdOnNaLBkfJVYvQ== user@msf3
		EOM

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => dsa_public,
			:public => true
		)
		assert_equal("ad:64:88:d8:f6:78:65:d4:da:a9:ba:56:61:74:a5:1c",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => dsa_public, 
			:format => :compact,
			:public => true
		)

		assert_equal("ad6488d8f67865d4daa9ba566174a51c",fp)

		fp = Net::SSH::Utils::Key.fingerprint(
			:data => dsa_public, 
			:format => :bin,
			:public => true
		)
		assert_equal("\xad\x64\x88\xd8\xf6\x78\x65\xd4\xda\xa9\xba\x56\x61\x74\xa5\x1c",fp)

		assert_raise OpenSSL::PKey::PKeyError do
			Net::SSH::Utils::Key.fingerprint(
				:data => dsa_public,
				:public => false
			)
		end
	end

	# Notice how it's currently impossible to tell if a key is
	# simply mistyped as a public or private key, or if it's a
	# badly formatted key. Too bad.
	def test_bogus_raise
		bogus_key = "Oh hey I'm a key. Ok, not really."
		assert_raise OpenSSL::PKey::PKeyError do 
			Net::SSH::Utils::Key.fingerprint(:data => bogus_key)
		end
	end

end
