# frozen_string_literal: true

RSpec.describe Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter do
  subject do
    described_class.new(ccache)
  end

  let(:ccache) do
    raw = "\x05\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0f" \
          "\x57\x49\x4e\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00" \
          "\x00\x00\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72" \
          "\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0f\x57\x49\x4e\x44" \
          "\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x00\x00\x0d\x41" \
          "\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x00\x00\x00\x01" \
          "\x00\x00\x00\x02\x00\x00\x00\x0f\x57\x49\x4e\x44\x4f\x4d\x41\x49" \
          "\x4e\x2e\x4c\x4f\x43\x41\x4c\x00\x00\x00\x06\x6b\x72\x62\x74\x67" \
          "\x74\x00\x00\x00\x0f\x57\x49\x4e\x44\x4f\x4d\x41\x49\x4e\x2e\x4c" \
          "\x4f\x43\x41\x4c\x00\x12\x00\x00\x00\x20\x38\x35\x36\x62\x38\x64" \
          "\x62\x61\x36\x37\x36\x32\x61\x61\x39\x30\x37\x38\x65\x66\x63\x31" \
          "\x33\x61\x35\x35\x32\x39\x34\x33\x37\x39\x63\x84\xd9\x01\x63\x84" \
          "\xd9\x01\x76\x50\xdc\x01\x76\x50\xdc\x01\x00\x50\xe0\x00\x00\x00" \
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xd1\x61\x82\x03\xcd\x30" \
          "\x82\x03\xc9\xa0\x03\x02\x01\x05\xa1\x11\x1b\x0f\x57\x49\x4e\x44" \
          "\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41\x4c\xa2\x24\x30\x22\xa0" \
          "\x03\x02\x01\x01\xa1\x1b\x30\x19\x1b\x06\x6b\x72\x62\x74\x67\x74" \
          "\x1b\x0f\x57\x49\x4e\x44\x4f\x4d\x41\x49\x4e\x2e\x4c\x4f\x43\x41" \
          "\x4c\xa3\x82\x03\x87\x30\x82\x03\x83\xa0\x03\x02\x01\x12\xa1\x03" \
          "\x02\x01\x02\xa2\x82\x03\x75\x04\x82\x03\x71\x49\xf0\xa0\x79\xaf" \
          "\xf5\x27\x19\xeb\x09\x98\x7c\x4f\x1f\x8a\x07\xfc\xf9\xae\x36\xb1" \
          "\xa3\xc7\x1d\x9a\x24\x3e\x6d\xa0\x02\x78\x38\xc8\xf2\x1a\x21\x73" \
          "\xde\xf9\x1e\x3b\x75\xeb\xae\x37\xa5\x00\x61\x37\x0c\x8b\xbe\xac" \
          "\xbb\x3b\xd2\xc9\xb3\xe4\x20\xb7\x4f\xb7\x9d\x12\xd8\xb8\x71\x38" \
          "\x39\xa9\x76\x6a\xe7\xdf\x42\x40\x49\x0b\x07\xf9\x37\x26\x1e\x9d" \
          "\x12\xd8\xbd\xf9\xd7\xa6\x71\x70\x50\xbe\x2b\xee\xfc\xcb\xe2\xb1" \
          "\x16\x8f\x22\x1f\xb8\x17\x40\x0b\x7a\x3a\x35\x12\x5a\x1e\x76\xa4" \
          "\x77\x9a\x79\x09\x67\xb5\x81\x71\xb9\x8c\xda\x3c\x74\x8a\x91\x21" \
          "\xde\x73\x8e\xd9\x5b\x70\xbf\x18\xdc\x81\x1b\xba\x1b\x6f\x3d\xc9" \
          "\xe7\x67\xd1\x08\xbc\xc6\x43\xd6\x82\xd0\xb8\x9c\x9f\xf7\x72\xed" \
          "\xe2\xc3\x38\x01\x90\xcc\x7d\xa3\xb3\x6c\x2e\x28\xe7\x42\xb4\xa1" \
          "\xcf\xb4\x70\x55\x0b\x22\x01\x2a\x4e\xe5\x0b\x84\x88\xfa\x24\x3e" \
          "\xdf\x71\x99\x52\x3b\xb3\xc3\x60\x3d\x99\xef\x32\x72\x34\xc4\xef" \
          "\xe6\xbf\xf9\xbf\x28\x26\xce\xe1\x4f\xb8\x62\x03\x12\x42\xad\x57" \
          "\xfb\x8e\x9b\x16\x70\x30\xd6\x25\x07\xed\xec\xc3\x3a\x7c\xbd\xa6" \
          "\x19\x42\x8e\xb7\xef\xcc\xfd\x3b\x52\x76\x9c\x0f\xcb\x4c\x58\x6e" \
          "\xc2\x9a\x08\x47\xe5\x6d\x63\x4f\x3c\x5a\x84\x29\x6f\xdb\x43\xf4" \
          "\x11\x8e\x28\x7d\x16\xc4\x32\xaf\x8f\x97\xe5\xf6\x59\x7a\x59\x8f" \
          "\x7d\x5e\xb5\x66\x65\x06\x70\x8e\x93\xfd\xed\x26\xad\x4e\x64\xa9" \
          "\x1a\x6a\x6c\xcc\x2b\x02\xa6\xaf\x8f\xfd\x96\xb2\xf0\x7c\x19\x5a" \
          "\x37\x5c\x47\xa3\x84\x3f\x56\x26\xa3\x2e\x84\x83\x5c\x80\x22\x23" \
          "\x24\xe6\x04\x65\x56\x96\xbe\xc1\x90\x26\x4c\xe5\xcc\xa4\x81\x6a" \
          "\x92\x90\xb9\xbc\x54\xae\xf4\xe5\x29\xd2\xa8\x06\x6d\x27\x2e\xb1" \
          "\x9e\xb8\x23\xbc\xa5\x4b\xc2\xa9\xcb\xc0\x13\xd1\xc0\x5a\x49\x44" \
          "\xef\x0c\x0c\x50\x89\xdf\x7e\x37\xae\x6e\xd3\xb4\xb9\x87\x6a\x81" \
          "\x91\xd3\xf9\x95\xb1\xfd\x40\x4e\x3a\x93\xe6\x7a\x1a\x7a\x6c\xe0" \
          "\xfd\x70\x34\x57\x1c\x17\xcb\xa4\x05\x6c\x84\xa2\xb9\x8f\xa0\xdd" \
          "\x69\x69\x96\x7d\xea\x5e\xca\x79\x1b\x40\xea\x44\x70\x37\x27\x7c" \
          "\x0b\xda\x76\xc8\xea\x23\x0c\x8e\xe4\xb1\x4e\x37\xa2\x36\x13\xe5" \
          "\x54\xb7\x6b\x47\x39\xa1\xd7\x2c\xd2\x9c\x80\xca\x1c\x72\xcd\x1f" \
          "\x75\xb6\x84\x64\x1c\x94\xb8\x07\xbc\xa5\x72\xe1\x6d\x05\x0e\x47" \
          "\x72\x05\x17\x3a\x05\x47\xbb\x85\x63\x2f\x92\xe5\xf1\xd6\x3f\x40" \
          "\xce\xd5\x6b\x49\xea\x0e\xdd\x91\xb4\x8c\x0f\xaf\x7f\xc5\xb9\xa4" \
          "\x45\xb8\x32\xa5\x47\x7c\xd3\x16\xa7\xf7\x1f\x40\xc3\x8c\xb0\xf7" \
          "\xed\x54\x54\xee\xd7\xe6\xe4\xbf\x27\x25\x9f\x61\xce\x60\x3f\x9d" \
          "\xde\xca\x0a\x0f\x44\x9b\x9d\x91\xdb\xce\xde\x59\xc6\x76\x2c\xd5" \
          "\xaa\x24\x45\xd7\x2e\x1e\xdd\x9f\x86\x84\xe9\x9e\x0c\x9e\xdd\xac" \
          "\x22\xa0\x42\x04\xbc\x4b\x96\x7f\x9e\x3c\x66\x24\x3b\x82\xa8\x05" \
          "\x34\xc4\x7d\xe3\x78\xc5\x40\xbf\x65\xf3\x3e\xc0\x8e\xea\x2e\x1f" \
          "\x6a\x77\x04\x65\xb6\x66\xab\x02\xa0\x64\xda\x75\x9e\x1b\x37\xb8" \
          "\xb6\x4c\x38\xe8\x7d\xaa\x19\xde\x91\xad\xb2\x60\x8c\xd5\x30\xc5" \
          "\x7f\xca\x87\x21\x06\x74\x4a\x8a\x07\x66\x9a\x7f\xc7\xd1\x24\x8e" \
          "\x29\x24\xc2\x75\xfa\x94\x1a\xeb\xbf\x7a\x50\x3b\x72\xdf\x6c\x60" \
          "\xb9\xef\x2b\xd7\xfd\x10\x7f\x38\xa7\x9c\xc7\x10\x7d\x05\x6a\x7c" \
          "\x61\x9a\xcf\x05\x66\xee\xcc\x28\xf1\xa4\xf5\x05\x31\xa6\x88\xec" \
          "\x7a\x88\x79\x41\xa0\x89\x10\xdc\x70\x94\x95\x6f\xfd\xca\x70\xdb" \
          "\xa7\x64\x81\x44\x5a\x83\xd3\xc9\xfe\xd5\xe4\x20\xdf\xd7\x65\x17" \
          "\xe3\x55\x7c\x1e\xd1\xba\xd1\x44\xb3\x80\x44\x17\xf5\x1d\x2e\xbe" \
          "\x74\xff\x4c\x4a\xad\x9c\xd9\x10\x1b\x90\x49\xbf\xcb\x59\xa8\x20" \
          "\x09\xa9\x21\x3e\x88\x5f\x05\x50\x6b\x54\x4b\xa8\x1f\xd4\xc3\x84" \
          "\xd6\x6b\x3a\xb9\xda\x28\x28\xb4\x6b\x06\x99\x42\xbb\xd7\x3c\xc9" \
          "\xea\xbd\x5a\x81\x60\xcd\xd2\xb1\x94\x57\x3a\x00\xeb\x72\xaf\xd3" \
          "\xef\xda\x91\xf5\xc0\xaf\x99\x04\xf6\x86\x1b\x26\xae\x1e\x1c\xd7" \
          "\x99\x5d\x56\x92\x29\x99\xe4\x76\x61\x2f\xe6\xb2\x79\x3b\x89\x55" \
          "\x61\x3e\xa7\x9c\xfe\x39\x15\x4e\xfa\x41\xef\xf1\x00\x00\x00\x00"

    Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.read(raw)
  end

  let(:key) { ['4b912be0366a6f37f4a7d571bee18b1173d93195ef76f8d1e3e81ef6172ab326'].pack('H*') }

  let(:no_decryption_example) do
    cipher = <<~CIPHER.lines(chomp: true).join('')
      SfCgea/1JxnrCZh8Tx+KB/z5rjaxo8cdmiQ+baACeDjI8hohc975Hjt16643pQBhNwyLvqy7
      O9LJs+Qgt0+3nRLYuHE4Oal2auffQkBJCwf5NyYenRLYvfnXpnFwUL4r7vzL4rEWjyIfuBdA
      C3o6NRJaHnakd5p5CWe1gXG5jNo8dIqRId5zjtlbcL8Y3IEbuhtvPcnnZ9EIvMZD1oLQuJyf
      93Lt4sM4AZDMfaOzbC4o50K0oc+0cFULIgEqTuULhIj6JD7fcZlSO7PDYD2Z7zJyNMTv5r/5
      vygmzuFPuGIDEkKtV/uOmxZwMNYlB+3swzp8vaYZQo6378z9O1J2nA/LTFhuwpoIR+VtY088
      WoQpb9tD9BGOKH0WxDKvj5fl9ll6WY99XrVmZQZwjpP97SatTmSpGmpszCsCpq+P/Zay8HwZ
      WjdcR6OEP1Ymoy6Eg1yAIiMk5gRlVpa+wZAmTOXMpIFqkpC5vFSu9OUp0qgGbScusZ64I7yl
      S8Kpy8AT0cBaSUTvDAxQid9+N65u07S5h2qBkdP5lbH9QE46k+Z6Gnps4P1wNFccF8ukBWyE
      ormPoN1paZZ96l7KeRtA6kRwNyd8C9p2yOojDI7ksU43ojYT5VS3a0c5odcs0pyAyhxyzR91
      toRkHJS4B7ylcuFtBQ5HcgUXOgVHu4VjL5Ll8dY/QM7Va0nqDt2RtIwPr3/FuaRFuDKlR3zT
      Fqf3H0DDjLD37VRU7tfm5L8nJZ9hzmA/nd7KCg9Em52R287eWcZ2LNWqJEXXLh7dn4aE6Z4M
      nt2sIqBCBLxLln+ePGYkO4KoBTTEfeN4xUC/ZfM+wI7qLh9qdwRltmarAqBk2nWeGze4tkw4
      6H2qGd6RrbJgjNUwxX/KhyEGdEqKB2aaf8fRJI4pJMJ1+pQa6796UDty32xgue8r1/0Qfzin
      nMcQfQVqfGGazwVm7swo8aT1BTGmiOx6iHlBoIkQ3HCUlW/9ynDbp2SBRFqD08n+1eQg39dl
      F+NVfB7RutFEs4BEF/UdLr50/0xKrZzZEBuQSb/LWaggCakhPohfBVBrVEuoH9TDhNZrOrna
      KCi0awaZQrvXPMnqvVqBYM3SsZRXOgDrcq/T79qR9cCvmQT2hhsmrh4c15ldVpIpmeR2YS/m
      snk7iVVhPqec/jkVTvpB7/E=
    CIPHER

    <<~EOF.rstrip
      Primary Principal: Administrator@WINDOMAIN.LOCAL
      Ccache version: 4

      Creds: 1
        Credential[0]:
          Server: krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL
          Client: Administrator@WINDOMAIN.LOCAL
          Ticket etype: 18 (AES256)
          Key: 3835366238646261363736326161393037386566633133613535323934333739
          Subkey: false
          Ticket Length: 977
          Ticket Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
          Addresses: 0
          Authdatas: 0
          Times:
            Auth time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
            Start time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
            End time: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
            Renew Till: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
          Ticket:
            Ticket Version Number: 5
            Realm: WINDOMAIN.LOCAL
            Server Name: krbtgt/WINDOMAIN.LOCAL
            Encrypted Ticket Part:
              Ticket etype: 18 (AES256)
              Key Version Number: 2
              Cipher:
                #{cipher}
    EOF
  end

  let(:decrypted_example) do
    <<~EOF.rstrip
      Primary Principal: Administrator@WINDOMAIN.LOCAL
      Ccache version: 4

      Creds: 1
        Credential[0]:
          Server: krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL
          Client: Administrator@WINDOMAIN.LOCAL
          Ticket etype: 18 (AES256)
          Key: 3835366238646261363736326161393037386566633133613535323934333739
          Subkey: false
          Ticket Length: 977
          Ticket Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
          Addresses: 0
          Authdatas: 0
          Times:
            Auth time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
            Start time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
            End time: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
            Renew Till: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
          Ticket:
            Ticket Version Number: 5
            Realm: WINDOMAIN.LOCAL
            Server Name: krbtgt/WINDOMAIN.LOCAL
            Encrypted Ticket Part:
              Ticket etype: 18 (AES256)
              Key Version Number: 2
              Decrypted (with key: 4b912be0366a6f37f4a7d571bee18b1173d93195ef76f8d1e3e81ef6172ab326):
                Times:
                  Auth time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
                  Start time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
                  End time: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
                  Renew Till: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
                Client Addresses: 0
                Transited: tr_type: 0, Contents: ""
                Client Name: 'Administrator'
                Client Realm: 'WINDOMAIN.LOCAL'
                Ticket etype: 18 (AES256)
                Session Key: 3835366238646261363736326161393037386566633133613535323934333739
                Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
                PAC:
                  Validation Info:
                    Logon Time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
                    Logoff Time: Never Expires (inf)
                    Kick Off Time: Never Expires (inf)
                    Password Last Set: No Time Set (0)
                    Password Can Change: No Time Set (0)
                    Password Must Change: Never Expires (inf)
                    Logon Count: 0
                    Bad Password Count: 0
                    User ID: 500
                    Primary Group ID: 513
                    User Flags: 0
                      .... .... .... .... ..0. .... .... .... Used Lmv2 Auth And Ntlmv2 Session Key: The USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY bit is NOT SET
                      .... .... .... .... ...0 .... .... .... Used Lmv2 Auth And Session Key: The USED_LMV2_AUTH_AND_SESSION_KEY bit is NOT SET
                      .... .... .... .... .... 0... .... .... Used Ntlmv2 Auth And Session Key: The USED_NTLMV2_AUTH_AND_SESSION_KEY bit is NOT SET
                      .... .... .... .... .... .0.. .... .... Profile Path Populated: The PROFILE_PATH_POPULATED bit is NOT SET
                      .... .... .... .... .... ..0. .... .... Resource Group Ids: The RESOURCE_GROUP_IDS bit is NOT SET
                      .... .... .... .... .... ...0 .... .... Accepts Ntlmv2: The ACCEPTS_NTLMV2 bit is NOT SET
                      .... .... .... .... .... .... 0... .... Machine Account: The MACHINE_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .0.. .... Sub Authentication: The SUB_AUTHENTICATION bit is NOT SET
                      .... .... .... .... .... .... ..0. .... Extra Sids: The EXTRA_SIDS bit is NOT SET
                      .... .... .... .... .... .... .... 0... Lan Manager: The LAN_MANAGER bit is NOT SET
                      .... .... .... .... .... .... .... ..0. No Encryption: The NO_ENCRYPTION bit is NOT SET
                      .... .... .... .... .... .... .... ...0 Guest: The GUEST bit is NOT SET
                    User Session Key: 00000000000000000000000000000000
                    User Account Control: 528
                      .... .... ..0. .... .... .... .... .... Use Aes Keys: The USE_AES_KEYS bit is NOT SET
                      .... .... ...0 .... .... .... .... .... Partial Secrets Account: The PARTIAL_SECRETS_ACCOUNT bit is NOT SET
                      .... .... .... 0... .... .... .... .... No Auth Data Required: The NO_AUTH_DATA_REQUIRED bit is NOT SET
                      .... .... .... .0.. .... .... .... .... Trusted To Authenticate For Delegation: The TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit is NOT SET
                      .... .... .... ..0. .... .... .... .... Password Expired: The PASSWORD_EXPIRED bit is NOT SET
                      .... .... .... ...0 .... .... .... .... Dont Require Preauth: The DONT_REQUIRE_PREAUTH bit is NOT SET
                      .... .... .... .... 0... .... .... .... Use Des Key Only: The USE_DES_KEY_ONLY bit is NOT SET
                      .... .... .... .... .0.. .... .... .... Not Delegated: The NOT_DELEGATED bit is NOT SET
                      .... .... .... .... ..0. .... .... .... Trusted For Delegation: The TRUSTED_FOR_DELEGATION bit is NOT SET
                      .... .... .... .... ...0 .... .... .... Smartcard Required: The SMARTCARD_REQUIRED bit is NOT SET
                      .... .... .... .... .... 0... .... .... Encrypted Test Password Allowed: The ENCRYPTED_TEST_PASSWORD_ALLOWED bit is NOT SET
                      .... .... .... .... .... .0.. .... .... Account Auto Lock: The ACCOUNT_AUTO_LOCK bit is NOT SET
                      .... .... .... .... .... ..1. .... .... Dont Expire Password: The DONT_EXPIRE_PASSWORD bit is SET
                      .... .... .... .... .... ...0 .... .... Server Trust Account: The SERVER_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... 0... .... Workstation Trust Account: The WORKSTATION_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .0.. .... Interdomain Trust Account: The INTERDOMAIN_TRUST_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... ..0. .... Mns Logon Account: The MNS_LOGON_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... ...1 .... Normal Account: The NORMAL_ACCOUNT bit is SET
                      .... .... .... .... .... .... .... 0... Temp Duplicate Account: The TEMP_DUPLICATE_ACCOUNT bit is NOT SET
                      .... .... .... .... .... .... .... .0.. Password Not Required: The PASSWORD_NOT_REQUIRED bit is NOT SET
                      .... .... .... .... .... .... .... ..0. Home Directory Required: The HOME_DIRECTORY_REQUIRED bit is NOT SET
                      .... .... .... .... .... .... .... ...0 Account Disabled: The ACCOUNT_DISABLED bit is NOT SET
                    Sub Auth Status: 0
                    Last Successful Interactive Logon: No Time Set (0)
                    Last Failed Interactive Logon: No Time Set (0)
                    Failed Interactive Logon Count: 0
                    Extra SID Count: 0
                    Resource Group Count: 0
                    Group Count: 5
                    Group IDs:
                      Relative ID: 513
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 512
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 520
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 518
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                      Relative ID: 519
                      Attributes: 7
                        ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
                        .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
                        .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
                        .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
                        .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
                    Logon Domain ID: S-1-5-21-3541430928-2051711210-1391384369
                    Effective Name: 'Administrator'
                    Full Name: ''
                    Logon Script: ''
                    Profile Path: ''
                    Home Directory: ''
                    Home Directory Drive: ''
                    Logon Server: ''
                    Logon Domain Name: 'WINDOMAIN.LOCAL'
                  Client Info:
                    Name: 'Administrator'
                    Client ID: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
                  Pac Server Checksum:
                    Signature: 5eb9400bcab42babcd598210
                  Pac Privilege Server Checksum:
                    Signature: 5858aff19f89c9b9ce01c437
    EOF
  end

  describe '#present' do
    context 'when decryption key is not provided' do
      it 'returns a string not containing pac info' do
        expect(subject.present).to eq(no_decryption_example)
      end
    end

    context 'when the incorrect decryption key is provided' do
      it 'raises an exception' do
        expect { subject.present(key: "a wrong key that's 32 bytes long") }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError)
      end
    end

    context 'when the decryption key is invalid' do
      it 'raises an exception' do
        expect { subject.present(key: 'key length must be') }.to raise_error(Rex::Proto::Kerberos::Model::Error::KerberosError)
      end
    end

    context 'when the correct decryption key is provided' do
      it 'returns a string containing pac info' do
        expect(subject.present(key: key)).to eq(decrypted_example)
      end
    end
  end

  describe '#present_upn_and_dns_information' do
    let(:upn) { 'test@windomain.local' }
    let(:dns_domain_name) { 'WINDOMAIN.LOCAL' }
    let(:sam_name) { 'test' }
    let(:sid) { 'S-1-5-32-544' }

    context 'with no sam name or sid' do
      let(:flags) { 0b01 }
      let(:upn_and_dns_info) do
        Rex::Proto::Kerberos::Pac::Krb5UpnDnsInfo.new(upn: upn, dns_domain_name: dns_domain_name, flags: flags)
      end
      it 'returns the correct string' do
        expect(subject.present_upn_and_dns_information(upn_and_dns_info)).to eq <<~EOF.rstrip
          UPN and DNS Information:
            UPN: test@windomain.local
            DNS Domain Name: WINDOMAIN.LOCAL
            Flags: 1
              .... .... .... .... .... .... .... ..0. Sam Name And Sid: The SAM_NAME_AND_SID bit is NOT SET
              .... .... .... .... .... .... .... ...1 Upn Name Constructed: The UPN_NAME_CONSTRUCTED bit is SET
        EOF
      end
    end

    context 'with sam name and sid' do
      let(:flags) { 0b11 }
      let(:upn_and_dns_info) do
        Rex::Proto::Kerberos::Pac::Krb5UpnDnsInfo.new(
          upn: upn, dns_domain_name: dns_domain_name, sam_name: sam_name, sid: sid, flags: flags
        )
      end
      it 'returns the correct string' do
        expect(subject.present_upn_and_dns_information(upn_and_dns_info)).to eq <<~EOF.rstrip
          UPN and DNS Information:
            UPN: test@windomain.local
            DNS Domain Name: WINDOMAIN.LOCAL
            Flags: 3
              .... .... .... .... .... .... .... ..1. Sam Name And Sid: The SAM_NAME_AND_SID bit is SET
              .... .... .... .... .... .... .... ...1 Upn Name Constructed: The UPN_NAME_CONSTRUCTED bit is SET
            SAM Name: test
            SID: S-1-5-32-544
        EOF
      end
    end

    describe '#print_bin_data_model' do
      context 'when the bindata object has fields that are not 1bit' do
        it 'should raise an exception' do
          model = Rex::Proto::Kerberos::Pac::UserSessionKey.new
          expect { subject.print_bin_data_model(model) }.to raise_error TypeError, 'Unsupported field type RubySMB::Dcerpc::Ndr::NdrFixArray for field :session_key - expected one of BinData::Bit1'
        end
      end

      context 'when a bit length less than the number of flags is passed' do
        it 'should raise an exception' do
          binary_value = [Rex::Proto::Kerberos::Pac::SE_GROUP_ALL].pack('N')
          group_attributes = Rex::Proto::Kerberos::Pac::GroupAttributes.read(binary_value)
          expect { subject.print_bin_data_model(group_attributes, bit_length: 2) }.to raise_error ArgumentError, 'Not implemented. Bit length(2) should equal the bit length of the model 32'
        end
      end

      context 'when passed GroupAttributes' do
        it 'should format flags when the SE_GROUP_RESOURCE flags are set' do
          binary_value = [Rex::Proto::Kerberos::Pac::SE_GROUP_RESOURCE].pack('N')
          group_attributes = Rex::Proto::Kerberos::Pac::GroupAttributes.read(binary_value)
          expect(subject.print_bin_data_model(group_attributes)).to match_table <<~TABLE
            ..1. .... .... .... .... .... .... .... Resource: The RESOURCE bit is SET
            .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
            .... .... .... .... .... .... .... .0.. Enabled: The ENABLED bit is NOT SET
            .... .... .... .... .... .... .... ..0. Enabled By Default: The ENABLED_BY_DEFAULT bit is NOT SET
            .... .... .... .... .... .... .... ...0 Mandatory: The MANDATORY bit is NOT SET
          TABLE
        end

        it 'should format flags when the SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED flags are set' do
          binary_value = [Rex::Proto::Kerberos::Pac::SE_GROUP_ALL].pack('N')
          group_attributes = Rex::Proto::Kerberos::Pac::GroupAttributes.read(binary_value)
          expect(subject.print_bin_data_model(group_attributes)).to match_table <<~TABLE
            ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
            .... .... .... .... .... .... .... 0... Owner: The OWNER bit is NOT SET
            .... .... .... .... .... .... .... .1.. Enabled: The ENABLED bit is SET
            .... .... .... .... .... .... .... ..1. Enabled By Default: The ENABLED_BY_DEFAULT bit is SET
            .... .... .... .... .... .... .... ...1 Mandatory: The MANDATORY bit is SET
          TABLE
        end

        it 'should format flags when the SE_GROUP_OWNER flag is set' do
          binary_value = [Rex::Proto::Kerberos::Pac::SE_GROUP_OWNER].pack('N')
          group_attributes = Rex::Proto::Kerberos::Pac::GroupAttributes.read(binary_value)
          expect(subject.print_bin_data_model(group_attributes)).to match_table <<~TABLE
            ..0. .... .... .... .... .... .... .... Resource: The RESOURCE bit is NOT SET
            .... .... .... .... .... .... .... 1... Owner: The OWNER bit is SET
            .... .... .... .... .... .... .... .0.. Enabled: The ENABLED bit is NOT SET
            .... .... .... .... .... .... .... ..0. Enabled By Default: The ENABLED_BY_DEFAULT bit is NOT SET
            .... .... .... .... .... .... .... ...0 Mandatory: The MANDATORY bit is NOT SET
          TABLE
        end
      end

      context 'when passed UserFlagsAttributes' do
        it 'should return formatted user descriptions for nothing being set' do
          binary_value = [0].pack('N')
          user_attributes = Rex::Proto::Kerberos::Pac::UserFlagAttributes.read(binary_value)
          expect(subject.print_bin_data_model(user_attributes)).to match_table <<~TABLE
            .... .... .... .... ..0. .... .... .... Used Lmv2 Auth And Ntlmv2 Session Key: The USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY bit is NOT SET
            .... .... .... .... ...0 .... .... .... Used Lmv2 Auth And Session Key: The USED_LMV2_AUTH_AND_SESSION_KEY bit is NOT SET
            .... .... .... .... .... 0... .... .... Used Ntlmv2 Auth And Session Key: The USED_NTLMV2_AUTH_AND_SESSION_KEY bit is NOT SET
            .... .... .... .... .... .0.. .... .... Profile Path Populated: The PROFILE_PATH_POPULATED bit is NOT SET
            .... .... .... .... .... ..0. .... .... Resource Group Ids: The RESOURCE_GROUP_IDS bit is NOT SET
            .... .... .... .... .... ...0 .... .... Accepts Ntlmv2: The ACCEPTS_NTLMV2 bit is NOT SET
            .... .... .... .... .... .... 0... .... Machine Account: The MACHINE_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .0.. .... Sub Authentication: The SUB_AUTHENTICATION bit is NOT SET
            .... .... .... .... .... .... ..0. .... Extra Sids: The EXTRA_SIDS bit is NOT SET
            .... .... .... .... .... .... .... 0... Lan Manager: The LAN_MANAGER bit is NOT SET
            .... .... .... .... .... .... .... ..0. No Encryption: The NO_ENCRYPTION bit is NOT SET
            .... .... .... .... .... .... .... ...0 Guest: The GUEST bit is NOT SET
          TABLE
        end

        it 'should return formatted user descriptions for MACHINE_ACCOUNT being set' do
          binary_value = [32].pack('N')
          user_attributes = Rex::Proto::Kerberos::Pac::UserFlagAttributes.read(binary_value)
          expect(subject.print_bin_data_model(user_attributes)).to match_table <<~TABLE
            .... .... .... .... ..0. .... .... .... Used Lmv2 Auth And Ntlmv2 Session Key: The USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY bit is NOT SET
            .... .... .... .... ...0 .... .... .... Used Lmv2 Auth And Session Key: The USED_LMV2_AUTH_AND_SESSION_KEY bit is NOT SET
            .... .... .... .... .... 0... .... .... Used Ntlmv2 Auth And Session Key: The USED_NTLMV2_AUTH_AND_SESSION_KEY bit is NOT SET
            .... .... .... .... .... .0.. .... .... Profile Path Populated: The PROFILE_PATH_POPULATED bit is NOT SET
            .... .... .... .... .... ..0. .... .... Resource Group Ids: The RESOURCE_GROUP_IDS bit is NOT SET
            .... .... .... .... .... ...0 .... .... Accepts Ntlmv2: The ACCEPTS_NTLMV2 bit is NOT SET
            .... .... .... .... .... .... 0... .... Machine Account: The MACHINE_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .0.. .... Sub Authentication: The SUB_AUTHENTICATION bit is NOT SET
            .... .... .... .... .... .... ..1. .... Extra Sids: The EXTRA_SIDS bit is SET
            .... .... .... .... .... .... .... 0... Lan Manager: The LAN_MANAGER bit is NOT SET
            .... .... .... .... .... .... .... ..0. No Encryption: The NO_ENCRYPTION bit is NOT SET
            .... .... .... .... .... .... .... ...0 Guest: The GUEST bit is NOT SET
          TABLE
        end

        it 'should return formatted user descriptions for USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY, NO_ENCRYPTION and GUEST being set' do
          binary_value = [8195].pack('N')
          user_attributes = Rex::Proto::Kerberos::Pac::UserFlagAttributes.read(binary_value)
          expect(subject.print_bin_data_model(user_attributes)).to match_table <<~TABLE
            .... .... .... .... ..1. .... .... .... Used Lmv2 Auth And Ntlmv2 Session Key: The USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY bit is SET
            .... .... .... .... ...0 .... .... .... Used Lmv2 Auth And Session Key: The USED_LMV2_AUTH_AND_SESSION_KEY bit is NOT SET
            .... .... .... .... .... 0... .... .... Used Ntlmv2 Auth And Session Key: The USED_NTLMV2_AUTH_AND_SESSION_KEY bit is NOT SET
            .... .... .... .... .... .0.. .... .... Profile Path Populated: The PROFILE_PATH_POPULATED bit is NOT SET
            .... .... .... .... .... ..0. .... .... Resource Group Ids: The RESOURCE_GROUP_IDS bit is NOT SET
            .... .... .... .... .... ...0 .... .... Accepts Ntlmv2: The ACCEPTS_NTLMV2 bit is NOT SET
            .... .... .... .... .... .... 0... .... Machine Account: The MACHINE_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .0.. .... Sub Authentication: The SUB_AUTHENTICATION bit is NOT SET
            .... .... .... .... .... .... ..0. .... Extra Sids: The EXTRA_SIDS bit is NOT SET
            .... .... .... .... .... .... .... 0... Lan Manager: The LAN_MANAGER bit is NOT SET
            .... .... .... .... .... .... .... ..1. No Encryption: The NO_ENCRYPTION bit is SET
            .... .... .... .... .... .... .... ...1 Guest: The GUEST bit is SET
          TABLE
        end

        it 'should return formatted user descriptions for every flag being set' do
          binary_value = [16363].pack('N')
          user_attributes = Rex::Proto::Kerberos::Pac::UserFlagAttributes.read(binary_value)
          expect(subject.print_bin_data_model(user_attributes)).to match_table <<~TABLE
            .... .... .... .... ..1. .... .... .... Used Lmv2 Auth And Ntlmv2 Session Key: The USED_LMV2_AUTH_AND_NTLMV2_SESSION_KEY bit is SET
            .... .... .... .... ...1 .... .... .... Used Lmv2 Auth And Session Key: The USED_LMV2_AUTH_AND_SESSION_KEY bit is SET
            .... .... .... .... .... 1... .... .... Used Ntlmv2 Auth And Session Key: The USED_NTLMV2_AUTH_AND_SESSION_KEY bit is SET
            .... .... .... .... .... .1.. .... .... Profile Path Populated: The PROFILE_PATH_POPULATED bit is SET
            .... .... .... .... .... ..1. .... .... Resource Group Ids: The RESOURCE_GROUP_IDS bit is SET
            .... .... .... .... .... ...1 .... .... Accepts Ntlmv2: The ACCEPTS_NTLMV2 bit is SET
            .... .... .... .... .... .... 1... .... Machine Account: The MACHINE_ACCOUNT bit is SET
            .... .... .... .... .... .... .1.. .... Sub Authentication: The SUB_AUTHENTICATION bit is SET
            .... .... .... .... .... .... ..1. .... Extra Sids: The EXTRA_SIDS bit is SET
            .... .... .... .... .... .... .... 1... Lan Manager: The LAN_MANAGER bit is SET
            .... .... .... .... .... .... .... ..1. No Encryption: The NO_ENCRYPTION bit is SET
            .... .... .... .... .... .... .... ...1 Guest: The GUEST bit is SET
          TABLE
        end
      end

      context 'when passed UserAccountAttributes' do
        it 'should return formatted user account descriptions for nothing being set' do
          binary_value = [0].pack('N')
          useraccount_attributes = Rex::Proto::Kerberos::Pac::UserAccountAttributes.read(binary_value)
          expect(subject.print_bin_data_model(useraccount_attributes)).to match_table <<~TABLE
            .... .... ..0. .... .... .... .... .... Use Aes Keys: The USE_AES_KEYS bit is NOT SET
            .... .... ...0 .... .... .... .... .... Partial Secrets Account: The PARTIAL_SECRETS_ACCOUNT bit is NOT SET
            .... .... .... 0... .... .... .... .... No Auth Data Required: The NO_AUTH_DATA_REQUIRED bit is NOT SET
            .... .... .... .0.. .... .... .... .... Trusted To Authenticate For Delegation: The TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit is NOT SET
            .... .... .... ..0. .... .... .... .... Password Expired: The PASSWORD_EXPIRED bit is NOT SET
            .... .... .... ...0 .... .... .... .... Dont Require Preauth: The DONT_REQUIRE_PREAUTH bit is NOT SET
            .... .... .... .... 0... .... .... .... Use Des Key Only: The USE_DES_KEY_ONLY bit is NOT SET
            .... .... .... .... .0.. .... .... .... Not Delegated: The NOT_DELEGATED bit is NOT SET
            .... .... .... .... ..0. .... .... .... Trusted For Delegation: The TRUSTED_FOR_DELEGATION bit is NOT SET
            .... .... .... .... ...0 .... .... .... Smartcard Required: The SMARTCARD_REQUIRED bit is NOT SET
            .... .... .... .... .... 0... .... .... Encrypted Test Password Allowed: The ENCRYPTED_TEST_PASSWORD_ALLOWED bit is NOT SET
            .... .... .... .... .... .0.. .... .... Account Auto Lock: The ACCOUNT_AUTO_LOCK bit is NOT SET
            .... .... .... .... .... ..0. .... .... Dont Expire Password: The DONT_EXPIRE_PASSWORD bit is NOT SET
            .... .... .... .... .... ...0 .... .... Server Trust Account: The SERVER_TRUST_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... 0... .... Workstation Trust Account: The WORKSTATION_TRUST_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .0.. .... Interdomain Trust Account: The INTERDOMAIN_TRUST_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... ..0. .... Mns Logon Account: The MNS_LOGON_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... ...0 .... Normal Account: The NORMAL_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .... 0... Temp Duplicate Account: The TEMP_DUPLICATE_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .... .0.. Password Not Required: The PASSWORD_NOT_REQUIRED bit is NOT SET
            .... .... .... .... .... .... .... ..0. Home Directory Required: The HOME_DIRECTORY_REQUIRED bit is NOT SET
            .... .... .... .... .... .... .... ...0 Account Disabled: The ACCOUNT_DISABLED bit is NOT SET
          TABLE
        end

        it 'should return formatted user account descriptions for DONT_EXPIRE_PASSWORD and NORMAL_ACCOUNT being set' do
          binary_value = [528].pack('N')
          useraccount_attributes = Rex::Proto::Kerberos::Pac::UserAccountAttributes.read(binary_value)
          expect(subject.print_bin_data_model(useraccount_attributes)).to match_table <<~TABLE
            .... .... ..0. .... .... .... .... .... Use Aes Keys: The USE_AES_KEYS bit is NOT SET
            .... .... ...0 .... .... .... .... .... Partial Secrets Account: The PARTIAL_SECRETS_ACCOUNT bit is NOT SET
            .... .... .... 0... .... .... .... .... No Auth Data Required: The NO_AUTH_DATA_REQUIRED bit is NOT SET
            .... .... .... .0.. .... .... .... .... Trusted To Authenticate For Delegation: The TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit is NOT SET
            .... .... .... ..0. .... .... .... .... Password Expired: The PASSWORD_EXPIRED bit is NOT SET
            .... .... .... ...0 .... .... .... .... Dont Require Preauth: The DONT_REQUIRE_PREAUTH bit is NOT SET
            .... .... .... .... 0... .... .... .... Use Des Key Only: The USE_DES_KEY_ONLY bit is NOT SET
            .... .... .... .... .0.. .... .... .... Not Delegated: The NOT_DELEGATED bit is NOT SET
            .... .... .... .... ..0. .... .... .... Trusted For Delegation: The TRUSTED_FOR_DELEGATION bit is NOT SET
            .... .... .... .... ...0 .... .... .... Smartcard Required: The SMARTCARD_REQUIRED bit is NOT SET
            .... .... .... .... .... 0... .... .... Encrypted Test Password Allowed: The ENCRYPTED_TEST_PASSWORD_ALLOWED bit is NOT SET
            .... .... .... .... .... .0.. .... .... Account Auto Lock: The ACCOUNT_AUTO_LOCK bit is NOT SET
            .... .... .... .... .... ..1. .... .... Dont Expire Password: The DONT_EXPIRE_PASSWORD bit is SET
            .... .... .... .... .... ...0 .... .... Server Trust Account: The SERVER_TRUST_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... 0... .... Workstation Trust Account: The WORKSTATION_TRUST_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .0.. .... Interdomain Trust Account: The INTERDOMAIN_TRUST_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... ..0. .... Mns Logon Account: The MNS_LOGON_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... ...1 .... Normal Account: The NORMAL_ACCOUNT bit is SET
            .... .... .... .... .... .... .... 0... Temp Duplicate Account: The TEMP_DUPLICATE_ACCOUNT bit is NOT SET
            .... .... .... .... .... .... .... .0.. Password Not Required: The PASSWORD_NOT_REQUIRED bit is NOT SET
            .... .... .... .... .... .... .... ..0. Home Directory Required: The HOME_DIRECTORY_REQUIRED bit is NOT SET
            .... .... .... .... .... .... .... ...0 Account Disabled: The ACCOUNT_DISABLED bit is NOT SET
          TABLE
        end
      end
    end
  end
end
