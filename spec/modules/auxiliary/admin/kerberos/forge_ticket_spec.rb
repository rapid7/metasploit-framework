require 'rspec'

RSpec.describe 'kerberos keytab' do
  include_context 'Msf::UIDriver'
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'admin/kerberos/forge_ticket'
    )
  end

  before(:each) do
    Timecop.freeze(Time.parse('Jul 15, 2022 12:33:40.000000000 GMT'))
    subject.datastore['VERBOSE'] = true
    allow(driver).to receive(:input).and_return(driver_input)
    allow(driver).to receive(:output).and_return(driver_output)
    subject.init_ui(driver_input, driver_output)
  end

  after do
    Timecop.return
  end

  describe '#run' do
    context 'when forging golden tickets' do
      it 'generates a golden ticket' do
        subject.datastore['ACTION'] = 'FORGE_GOLDEN'
        subject.datastore['DOMAIN'] = 'demo.local'
        subject.datastore['DOMAIN_SID'] = 'S-1-5-21-1266190811-2419310613-1856291569'
        subject.datastore['NTHASH'] = '767400b2c71afa35a5dca216f2389cd9'
        subject.datastore['USER'] = 'Administrator'
        subject.datastore['RPORT'] = ''
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
        subject.datastore['EXTRA_SIDS'] = ' S-1-18-1,  S-1-5-21-1266190811-2419310613-1856291569-519, '
        subject.datastore['SessionKey'] = 'A' * 16

        subject.run

        ticket_save_path = @output.join("\n")[/Cache ticket saved to (.*)$/, 1]
        expect(@output.join("\n")).to match_table <<~TABLE
          TGT MIT Credential Cache ticket saved to #{ticket_save_path}
          Primary Principal: Administrator@DEMO.LOCAL
          Ccache version: 4

          Creds: 1
            Credential[0]:
              Server: krbtgt/DEMO.LOCAL@DEMO.LOCAL
              Client: Administrator@DEMO.LOCAL
              Ticket etype: 23 (RC4_HMAC)
              Key: 41414141414141414141414141414141
              Subkey: false
              Ticket Length: 1086
              Ticket Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
              Addresses: 0
              Authdatas: 0
              Times:
                Auth time: #{Time.parse('2022-07-15 13:33:40 +0100').localtime}
                Start time: #{Time.parse('2022-07-15 13:33:40 +0100').localtime}
                End time: #{Time.parse('2032-07-12 13:33:40 +0100').localtime}
                Renew Till: #{Time.parse('2032-07-12 13:33:40 +0100').localtime}
              Ticket:
                Ticket Version Number: 5
                Realm: DEMO.LOCAL
                Server Name: krbtgt/DEMO.LOCAL
                Encrypted Ticket Part:
                  Ticket etype: 23 (RC4_HMAC)
                  Key Version Number: 2
                  Decrypted (with key: 767400b2c71afa35a5dca216f2389cd9):
                    Times:
                      Auth time: #{Time.parse('2022-07-15 12:33:40 UTC').localtime}
                      Start time: #{Time.parse('2022-07-15 12:33:40 UTC').localtime}
                      End time: #{Time.parse('2032-07-12 12:33:40 UTC').localtime}
                      Renew Till: #{Time.parse('2032-07-12 12:33:40 UTC').localtime}
                    Client Addresses: 0
                    Transited: tr_type: 0, Contents: ""
                    Client Name: 'Administrator'
                    Client Realm: 'DEMO.LOCAL'
                    Ticket etype: 23 (RC4_HMAC)
                    Session Key: 41414141414141414141414141414141
                    Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
                    PAC:
                      Validation Info:
                        Logon Time: #{Time.parse('2022-07-15 13:33:40 +0100').localtime}
                        Logoff Time: Never Expires (inf)
                        Kick Off Time: Never Expires (inf)
                        Password Last Set: No Time Set (0)
                        Password Can Change: No Time Set (0)
                        Password Must Change: Never Expires (inf)
                        Logon Count: 0
                        Bad Password Count: 0
                        User ID: 500
                        Primary Group ID: 513
                        User Flags: 32
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
                        Extra SID Count: 2
                          SID: S-1-18-1, Attributes: 7
                          SID: S-1-5-21-1266190811-2419310613-1856291569-519, Attributes: 7
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
                        Logon Domain ID: S-1-5-21-1266190811-2419310613-1856291569
                        Effective Name: 'Administrator'
                        Full Name: ''
                        Logon Script: ''
                        Profile Path: ''
                        Home Directory: ''
                        Home Directory Drive: ''
                        Logon Server: ''
                        Logon Domain Name: 'DEMO.LOCAL'
                      Client Info:
                        Name: 'Administrator'
                        Client ID: #{Time.parse('2022-07-15 13:33:40 +0100').localtime}
                      Pac Requestor:
                        SID: S-1-5-21-1266190811-2419310613-1856291569-500
                      Pac Attributes:
                        Flag length: 2
                        Flags: 1
                          .... .... .... .... .... .... .... ..0. Pac Was Requested: The PAC_WAS_REQUESTED bit is NOT SET
                          .... .... .... .... .... .... .... ...1 Pac Was Given Implicitly: The PAC_WAS_GIVEN_IMPLICITLY bit is SET
                      Pac Server Checksum:
                        Signature: 0e081d0f36228b8b592c6947c8c96435
                      Pac Privilege Server Checksum:
                        Signature: 42ecbbbdeb8dae3fe42f7ac5630f3af3
        TABLE
        expect(ticket_save_path).to_not be_nil
      end
    end
  end
end
