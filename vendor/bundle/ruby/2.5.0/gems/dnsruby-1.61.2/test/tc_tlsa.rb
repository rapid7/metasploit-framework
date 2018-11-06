require_relative 'spec_helper'

require 'openssl'
require 'digest'

class TLSATest < Minitest::Test
  include Dnsruby

  INPUT = ['_443._tcp.example.jp. IN TLSA 3 0 1 ( 6609173804b9e31895f550db027ef7c7fa6f1bc9326c99371b61f1ba5 '\
            'cb3595d )',
           '_443._tcp.example.jp. IN TLSA 255 255 255 ( 6609173804b9e31895f550db027ef7c7fa6f1bc9326c99371b61f1ba5 '\
            'cb3595d )',
           '_443._tcp.data.iana.org. IN TLSA 3 0 0 ( 308206833082056ba003020102021009cabbe2191c8f569dd4b6dd250 '\
             'f21d8300d06092a864886f70d01010b05003070310b30090603550406 '\
             '1302555331153013060355040a130c446967694365727420496e63311 '\
             '93017060355040b13107777772e64696769636572742e636f6d312f30 '\
             '2d0603550403132644696769436572742053484132204869676820417 '\
             '3737572616e636520536572766572204341301e170d31343130323730 '\
             '30303030305a170d3138303130333132303030305a3081a3310b30090 '\
             '60355040613025553311330110603550408130a43616c69666f726e69 '\
             '61311430120603550407130b4c6f7320416e67656c6573313c303a060 '\
             '355040a1333496e7465726e657420436f72706f726174696f6e20666f '\
             '722041737369676e6564204e616d657320616e64204e756d626572733 '\
             '1163014060355040b130d4954204f7065726174696f6e733113301106 '\
             '035504030c0a2a2e69616e612e6f726730820222300d06092a864886f '\
             '70d01010105000382020f003082020a02820201009dbdfddeb5cae53a '\
             '559747e2fda63728e4aba60f18b79a69f03310bf0164e5ee7db6b15bf '\
             '56df23fddbae6a1bb38449b8c883f18102bbd8bb655ac0e2dac2ee3ed '\
             '5cf4315868d2c598068284854b24894dcd4bd37811f0ad3a282cd4b4e '\
             '599ffd07d8d2d3f2478554f81020b320ee12f44948e2ea1edbc990b83 '\
             '0ca5cca6b4a839fb27b51850c9847eac74f26609eb24365b9751fb1c3 '\
             '208f56913bacbcae49201347c78b7e54a9d99979404c37f00fb65db84 '\
             '9fd75e3a68770c30f2abe65b33256fb59b450050b00d8139d4d80d36f '\
             '7bc46daf303e48f0f0791b2fdd72ec60b2cb3ad533c3f288c9c194e49 '\
             '337a69c496731f086d4f1f9825900713e2a551d05cb6057567850d91e '\
             '6001c4ce27176f0957873a95b880acbec19e7bd9bcf1286d0452b7378 '\
             '9c41905dd470971cd73aea52c77b080cd779af58234f337225c26f87a '\
             '8c13e2a65e9dd4e03a5b41d7e06b3353f38129b2327a531ec9627a21d '\
             'c423733aa029d4989448ba3322891c1a5690ddf2d25c8ec8aaa894b14 '\
             'aa92130c6b6d969a21ff671b60c4c923a94a93ea1dd0492c93393ca6e '\
             'dd61f33ca77e9208d01d6bd15107662ec088733df4c876a7e1608b829 '\
             '73a0f7592e84ed15579d181e79024ae8a7e4b9f0078eb2005b23f9d09 '\
             'a1df1bbc7de2a5a6085a3646d9fadb0e9da273a5f403cdd42831ce6f0 '\
             'ca46889585602bb8bc36bb3be861ff6d1a62e350203010001a38201e3 '\
             '308201df301f0603551d230418301680145168ff90af0207753cccd96 '\
             '56462a212b859723b301d0603551d0e04160414c7d0acef898b20e4b9 '\
             '14668933032394f6bf3a61301f0603551d1104183016820a2a2e69616 '\
             'e612e6f7267820869616e612e6f7267300e0603551d0f0101ff040403 '\
             '0205a0301d0603551d250416301406082b0601050507030106082b060 '\
             '1050507030230750603551d1f046e306c3034a032a030862e68747470 '\
             '3a2f2f63726c332e64696769636572742e636f6d2f736861322d68612 '\
             'd7365727665722d67332e63726c3034a032a030862e687474703a2f2f '\
             '63726c342e64696769636572742e636f6d2f736861322d68612d73657 '\
             '27665722d67332e63726c30420603551d20043b303930370609608648 '\
             '0186fd6c0101302a302806082b06010505070201161c68747470733a2 '\
             'f2f7777772e64696769636572742e636f6d2f43505330818306082b06 '\
             '01050507010104773075302406082b060105050730018618687474703 '\
             'a2f2f6f6373702e64696769636572742e636f6d304d06082b06010505 '\
             '0730028641687474703a2f2f636163657274732e64696769636572742 '\
             'e636f6d2f446967694365727453484132486967684173737572616e63 '\
             '6553657276657243412e637274300c0603551d130101ff04023000300 '\
             'd06092a864886f70d01010b0500038201010070314c38e7c02fd80810 '\
             '500b9df6dae85de9b23e29fbd68bfdb5f23411c89acfaf9ae05af9123 '\
             'a8aa6bce6954a4e68dc7cfc480a65d76f229c4bd5f5674b0c9ac6d06a '\
             '37a1a1c145c3956120b8efe67c887ab4ff7d6aa950ff3698f27c4a19d '\
             '59d93a39aca5a7b6d6c75e34974e50f5a590005b3cb665ddbd7074f9f '\
             'cbcbf9c50228d5e25596b64ada160b48f77a93aaced22617bfe005e00 '\
             'fe20a532a0adcb818c878dc5d6649277777ca1a814e21d0b53308af40 '\
             '78be4554715e4ce4828b012f25ffa13a6ceb30d20a75deba8a344e41d '\
             '627fa638feff38a3063a0187519b39b053f7134d9cd83e6091accf5d2 '\
             'e3a05edfa1dfbe181a87ad86ba24fe6b97fe )',
           '_443._tcp.data.iana.org. IN TLSA 3 0 1 ( 2760bc55bbb8cf398e4c90da21018b2eaafc9e375f7428cf0708e7c88 '\
             '8261b49',
           '_443._tcp.data.iana.org. IN TLSA 3 0 2 ( e6f38e78b1c9f8e0969e81c555e2770eeccb3f120986558adfb2c48aa '\
             'dc6f85d3596f0cc7362a6a6cda7b6dea222a968fef5aeeaf6d334c8b9 '\
             '725543f27683db )',
           '_443._tcp.data.iana.org. IN TLSA 3 1 0 (30820222300d06092a864886f70d01010105000382020f003082020a0 '\
             '2820201009dbdfddeb5cae53a559747e2fda63728e4aba60f18b79a69 '\
             'f03310bf0164e5ee7db6b15bf56df23fddbae6a1bb38449b8c883f181 '\
             '02bbd8bb655ac0e2dac2ee3ed5cf4315868d2c598068284854b24894d '\
             'cd4bd37811f0ad3a282cd4b4e599ffd07d8d2d3f2478554f81020b320 '\
             'ee12f44948e2ea1edbc990b830ca5cca6b4a839fb27b51850c9847eac '\
             '74f26609eb24365b9751fb1c3208f56913bacbcae49201347c78b7e54 '\
             'a9d99979404c37f00fb65db849fd75e3a68770c30f2abe65b33256fb5 '\
             '9b450050b00d8139d4d80d36f7bc46daf303e48f0f0791b2fdd72ec60 '\
             'b2cb3ad533c3f288c9c194e49337a69c496731f086d4f1f9825900713 '\
             'e2a551d05cb6057567850d91e6001c4ce27176f0957873a95b880acbe '\
             'c19e7bd9bcf1286d0452b73789c41905dd470971cd73aea52c77b080c '\
             'd779af58234f337225c26f87a8c13e2a65e9dd4e03a5b41d7e06b3353 '\
             'f38129b2327a531ec9627a21dc423733aa029d4989448ba3322891c1a '\
             '5690ddf2d25c8ec8aaa894b14aa92130c6b6d969a21ff671b60c4c923 '\
             'a94a93ea1dd0492c93393ca6edd61f33ca77e9208d01d6bd15107662e '\
             'c088733df4c876a7e1608b82973a0f7592e84ed15579d181e79024ae8 '\
             'a7e4b9f0078eb2005b23f9d09a1df1bbc7de2a5a6085a3646d9fadb0e '\
             '9da273a5f403cdd42831ce6f0ca46889585602bb8bc36bb3be861ff6d '\
             '1a62e350203010001 )',
           '_443._tcp.data.iana.org. IN TLSA 3 1 1 ( d56f85824b6ed2ab15b9040c20b574515d9a0ab415ca253b42cbc915a '\
             '11de18d )',
           '_443._tcp.data.iana.org. IN TLSA 3 1 2 ( ba8b1b6f74782cb681373c314cf7bf4d2468c6a9dee47909fae1381ca '\
             '6447249c42cb2a4d6d808fa1486ba70b7c1bb70dd76657a281441110b '\
             'b4043007ee5ce3 )'
  ].freeze
  CERT = "-----BEGIN CERTIFICATE-----
MIIGgzCCBWugAwIBAgIQCcq74hkcj1ad1LbdJQ8h2DANBgkqhkiG9w0BAQsFADBw
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz
dXJhbmNlIFNlcnZlciBDQTAeFw0xNDEwMjcwMDAwMDBaFw0xODAxMDMxMjAwMDBa
MIGjMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxML
TG9zIEFuZ2VsZXMxPDA6BgNVBAoTM0ludGVybmV0IENvcnBvcmF0aW9uIGZvciBB
c3NpZ25lZCBOYW1lcyBhbmQgTnVtYmVyczEWMBQGA1UECxMNSVQgT3BlcmF0aW9u
czETMBEGA1UEAwwKKi5pYW5hLm9yZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAJ29/d61yuU6VZdH4v2mNyjkq6YPGLeaafAzEL8BZOXufbaxW/Vt8j/d
uuahuzhEm4yIPxgQK72LtlWsDi2sLuPtXPQxWGjSxZgGgoSFSySJTc1L03gR8K06
KCzUtOWZ/9B9jS0/JHhVT4ECCzIO4S9ElI4uoe28mQuDDKXMprSoOfsntRhQyYR+
rHTyZgnrJDZbl1H7HDII9WkTusvK5JIBNHx4t+VKnZmXlATDfwD7ZduEn9deOmh3
DDDyq+ZbMyVvtZtFAFCwDYE51NgNNve8RtrzA+SPDweRsv3XLsYLLLOtUzw/KIyc
GU5JM3ppxJZzHwhtTx+YJZAHE+KlUdBctgV1Z4UNkeYAHEzicXbwlXhzqVuICsvs
Gee9m88ShtBFK3N4nEGQXdRwlxzXOupSx3sIDNd5r1gjTzNyJcJvh6jBPipl6d1O
A6W0HX4GszU/OBKbIyelMeyWJ6IdxCNzOqAp1JiUSLozIokcGlaQ3fLSXI7IqqiU
sUqpITDGttlpoh/2cbYMTJI6lKk+od0Ekskzk8pu3WHzPKd+kgjQHWvRUQdmLsCI
cz30yHan4WCLgpc6D3WS6E7RVXnRgeeQJK6KfkufAHjrIAWyP50Jod8bvH3ipaYI
WjZG2frbDp2ic6X0A83UKDHObwykaIlYVgK7i8Nrs76GH/bRpi41AgMBAAGjggHj
MIIB3zAfBgNVHSMEGDAWgBRRaP+QrwIHdTzM2WVkYqISuFlyOzAdBgNVHQ4EFgQU
x9Cs74mLIOS5FGaJMwMjlPa/OmEwHwYDVR0RBBgwFoIKKi5pYW5hLm9yZ4IIaWFu
YS5vcmcwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
c2hhMi1oYS1zZXJ2ZXItZzMuY3JsMDSgMqAwhi5odHRwOi8vY3JsNC5kaWdpY2Vy
dC5jb20vc2hhMi1oYS1zZXJ2ZXItZzMuY3JsMEIGA1UdIAQ7MDkwNwYJYIZIAYb9
bAEBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMw
gYMGCCsGAQUFBwEBBHcwdTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
cnQuY29tME0GCCsGAQUFBzAChkFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
RGlnaUNlcnRTSEEySGlnaEFzc3VyYW5jZVNlcnZlckNBLmNydDAMBgNVHRMBAf8E
AjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBwMUw458Av2AgQUAud9troXemyPin71ov9
tfI0Eciaz6+a4Fr5EjqKprzmlUpOaNx8/EgKZddvIpxL1fVnSwyaxtBqN6GhwUXD
lWEguO/mfIh6tP99aqlQ/zaY8nxKGdWdk6Oaylp7bWx140l05Q9aWQAFs8tmXdvX
B0+fy8v5xQIo1eJVlrZK2hYLSPd6k6rO0iYXv+AF4A/iClMqCty4GMh43F1mSSd3
d8oagU4h0LUzCK9AeL5FVHFeTOSCiwEvJf+hOmzrMNIKdd66ijROQdYn+mOP7/OK
MGOgGHUZs5sFP3E02c2D5gkazPXS46Be36Hfvhgah62GuiT+a5f+
-----END CERTIFICATE-----".freeze

  def test_tlsa_from_string
    t1 = Dnsruby::RR.create(INPUT[0])
    assert_equal(3, t1.usage)
    assert_equal(0, t1.selector)
    assert_equal(1, t1.matching_type)
    assert_equal('6609173804b9e31895f550db027ef7c7fa6f1bc9326c99371b61f1ba5 cb3595d', t1.data)

    t2 = Dnsruby::RR.create(INPUT[1])
    assert_equal(255, t2.usage)
    assert_equal(255, t2.selector)
    assert_equal(255, t2.matching_type)
    assert_equal('6609173804b9e31895f550db027ef7c7fa6f1bc9326c99371b61f1ba5 cb3595d', t2.data)
  end

  def test_tlsa_from_data
    t1 = Dnsruby::RR.create(INPUT[0])
    m = Dnsruby::Message.new
    m.add_additional(t1)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    t3 = m2.additional[0]
    assert_equal(t1.to_s, t3.to_s)
  end

  def test_tlsa_verify_rsa_cert
    cert = OpenSSL::X509::Certificate.new(CERT)
    der = cert.to_der
    t4 = Dnsruby::RR.create(INPUT[2])
    assert_equal(t4.databin, der)

    t5 = Dnsruby::RR.create(INPUT[3])
    assert_equal(t5.databin, OpenSSL::Digest::SHA256.digest(der))

    t6 = Dnsruby::RR.create(INPUT[4])
    assert_equal(t6.databin, OpenSSL::Digest::SHA512.digest(der))
  end

  def test_tlsa_verify_rsa_pkey
    cert = OpenSSL::X509::Certificate.new(CERT)
    pkey = cert.public_key.to_der

    t7 = Dnsruby::RR.create(INPUT[5])
    assert_equal(t7.databin, pkey)

    t8 = Dnsruby::RR.create(INPUT[6])
    assert_equal(t8.databin, OpenSSL::Digest::SHA256.digest(pkey))

    t9 = Dnsruby::RR.create(INPUT[7])
    assert_equal(t9.databin, OpenSSL::Digest::SHA512.digest(pkey))
  end
end
