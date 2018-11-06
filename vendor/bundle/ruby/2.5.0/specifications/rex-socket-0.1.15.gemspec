# -*- encoding: utf-8 -*-
# stub: rex-socket 0.1.15 ruby lib

Gem::Specification.new do |s|
  s.name = "rex-socket".freeze
  s.version = "0.1.15"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["David Maloney".freeze]
  s.bindir = "exe".freeze
  s.cert_chain = ["-----BEGIN CERTIFICATE-----\nMIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\nA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\nZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\nMTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\nA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\nRgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\ngHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\nKPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\nQQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\nXriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\nLkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\nRUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\njjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\n6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\nmcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\nMx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\nWD9f\n-----END CERTIFICATE-----\n".freeze, "-----BEGIN CERTIFICATE-----\nMIIElDCCA3ygAwIBAgIOSBtqBybS6D8mAtSCWs0wDQYJKoZIhvcNAQELBQAwTDEg\nMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2Jh\nbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTYwNjE1MDAwMDAwWhcNMjQw\nNjE1MDAwMDAwWjBaMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBu\ndi1zYTEwMC4GA1UEAxMnR2xvYmFsU2lnbiBDb2RlU2lnbmluZyBDQSAtIFNIQTI1\nNiAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjYVVI6kfU6/J\n7TbCKbVu2PlC9SGLh/BDoS/AP5fjGEfUlk6Iq8Zj6bZJFYXx2Zt7G/3YSsxtToZA\nF817ukcotdYUQAyG7h5LM/MsVe4hjNq2wf6wTjquUZ+lFOMQ5pPK+vldsZCH7/g1\nLfyiXCbuexWLH9nDoZc1QbMw/XITrZGXOs5ynQYKdTwfmOPLGC+MnwhKkQrZ2TXZ\ng5J2Yl7fg67k1gFOzPM8cGFYNx8U42qgr2v02dJsLBkwXaBvUt/RnMngDdl1EWWW\n2UO0p5A5rkccVMuxlW4l3o7xEhzw127nFE2zGmXWhEpX7gSvYjjFEJtDjlK4Prau\nniyX/4507wIDAQABo4IBZDCCAWAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQG\nCCsGAQUFBwMDBggrBgEFBQcDCTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW\nBBQPOueslJF0LZYCc4OtnC5JPxmqVDAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpj\nmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3Nw\nMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDov\nL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBjBgNVHSAEXDBaMAsGCSsG\nAQQBoDIBMjAIBgZngQwBBAEwQQYJKwYBBAGgMgFfMDQwMgYIKwYBBQUHAgEWJmh0\ndHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB\nCwUAA4IBAQAVhCgM7aHDGYLbYydB18xjfda8zzabz9JdTAKLWBoWCHqxmJl/2DOK\nXJ5iCprqkMLFYwQL6IdYBgAHglnDqJQy2eAUTaDVI+DH3brwaeJKRWUtTUmQeGYy\nDrBowLCIsI7tXAb4XBBIPyNzujtThFKAzfCzFcgRCosFeEZZCNS+t/9L9ZxqTJx2\nohGFRYzUN+5Q3eEzNKmhHzoL8VZEim+zM9CxjtEMYAfuMsLwJG+/r/uBAXZnxKPo\n4KvcM1Uo42dHPOtqpN+U6fSmwIHRUphRptYCtzzqSu/QumXSN4NTS35nfIxA9gcc\nsK8EBtz4bEaIcpzrTp3DsLlUo7lOl8oU\n-----END CERTIFICATE-----\n".freeze, "-----BEGIN CERTIFICATE-----\nMIIE5jCCA86gAwIBAgIMKDuO03uv6RWXR1uAMA0GCSqGSIb3DQEBCwUAMFoxCzAJ\nBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTAwLgYDVQQDEydH\nbG9iYWxTaWduIENvZGVTaWduaW5nIENBIC0gU0hBMjU2IC0gRzMwHhcNMTYwOTEz\nMTgxMDIyWhcNMTkxMTExMTUxNTM4WjBgMQswCQYDVQQGEwJVUzEWMBQGA1UECBMN\nTWFzc2FjaHVzZXR0czEPMA0GA1UEBxMGQm9zdG9uMRMwEQYDVQQKEwpSYXBpZDcg\nTExDMRMwEQYDVQQDEwpSYXBpZDcgTExDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAl0HeC0FzN1BJ4nQkxsBng3peS9Bdi9rpSGx+g0Ximd+M/7twmund\nbzn2JPbNK/Gp/rq/SytrNSLcUzcbH/0z5Ltyw1/jQsGtRBrns0NZSRXqupQDW5R6\nHFpaIAl3OdsesmIQc/fm0uhh8dkfHVo7UsZO/TeCPoy0uHXTI6aFBPzMMsdz+gf3\ncCCLsnNKQh/T2Q/jwBs3NTPoyza/pPZcvGogKcWCeNihTO5Rn1Fc71sMHSjQsDtn\n1fWGKYGi0qjvZ4lpGM9IFZMTbySKHbPLhhHnBOoV7avGemdky3AEsUeiT+6DY0P1\nIydBy24uVNhGATglME1ttlT4Eme/to0M6wIDAQABo4IBpDCCAaAwDgYDVR0PAQH/\nBAQDAgeAMIGUBggrBgEFBQcBAQSBhzCBhDBIBggrBgEFBQcwAoY8aHR0cDovL3Nl\nY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Njb2Rlc2lnbnNoYTJnM29jc3Au\nY3J0MDgGCCsGAQUFBzABhixodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vZ3Nj\nb2Rlc2lnbnNoYTJnMzBWBgNVHSAETzBNMEEGCSsGAQQBoDIBMjA0MDIGCCsGAQUF\nBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAIBgZn\ngQwBBAEwCQYDVR0TBAIwADA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmds\nb2JhbHNpZ24uY29tL2dzY29kZXNpZ25zaGEyZzMuY3JsMBMGA1UdJQQMMAoGCCsG\nAQUFBwMDMB0GA1UdDgQWBBSm8RBpBC/cK9VmxzO2+RWnacN8CTAfBgNVHSMEGDAW\ngBQPOueslJF0LZYCc4OtnC5JPxmqVDANBgkqhkiG9w0BAQsFAAOCAQEANVO3uYQl\nh8iicbaXE3odrL+kXXmeeNgt4BD3x7GKAVIVixtwBS6pvrshjc1LN0tm3ruiv8oy\ncq4FiEmVUXZejSRvVVtABeWdZWo+lJ8NxCBUEYYmnMrjgFIbGiEbBsg7PGtyeQsA\n5Wbg7Lx889mS1tKfQBcPif8EjpTiXNfMiywmpaMYmvm+yQgzrRLDbjz6JV0Rc5Ga\nWChka+LTPnMtsWJuFM8ka8icMeS28/nAGERdewxWvz+DeAPMORdTJ7aqb6+Y9xuz\nG+Hmcg1v810agasPdoydE0RTVZgEOOMoQ07qu7JFXVWZ9ZQpHT7qJATWL/b2csFG\n8mVuTXnyJOKRJA==\n-----END CERTIFICATE-----\n".freeze]
  s.date = "2018-07-25"
  s.description = "The Ruby Exploitation (Rex) Socket Abstraction Library. This library\n                          includes all of the code needed to turn sockets into Rex::Sockets with the functionality\n                          for things like L3 pivoting used by Metasploit. ".freeze
  s.email = ["DMaloney@rapid7.com".freeze]
  s.homepage = "https://github.com/rapid7/rex-socket".freeze
  s.required_ruby_version = Gem::Requirement.new(">= 2.2.0".freeze)
  s.rubygems_version = "2.7.7".freeze
  s.summary = "The Ruby Exploitation (Rex) Socket Abstraction Library.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.12"])
      s.add_development_dependency(%q<rake>.freeze, ["~> 10.0"])
      s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0"])
      s.add_runtime_dependency(%q<rex-core>.freeze, [">= 0"])
    else
      s.add_dependency(%q<bundler>.freeze, ["~> 1.12"])
      s.add_dependency(%q<rake>.freeze, ["~> 10.0"])
      s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
      s.add_dependency(%q<rex-core>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<bundler>.freeze, ["~> 1.12"])
    s.add_dependency(%q<rake>.freeze, ["~> 10.0"])
    s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
    s.add_dependency(%q<rex-core>.freeze, [">= 0"])
  end
end
