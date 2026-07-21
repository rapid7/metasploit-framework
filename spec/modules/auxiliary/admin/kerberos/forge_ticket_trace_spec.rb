# frozen_string_literal: true

require 'rspec'

RSpec.describe 'kerberos forge ticket trace' do
  include_context 'Msf::UIDriver'
  include_context 'Msf::Simple::Framework#modules loading'

  let(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'admin/kerberos/forge_ticket'
    )
  end

  before(:each) do
    mod.datastore['VERBOSE'] = false
    allow(driver).to receive(:input).and_return(driver_input)
    allow(driver).to receive(:output).and_return(driver_output)
    mod.init_ui(driver_input, driver_output)
  end

  describe '#run' do
    it 'does not print forged ticket trace output when disabled' do
      configure_manual_ticket(action: 'FORGE_GOLDEN')
      mod.datastore['KerberosTicketTrace'] = 'off'

      mod.run

      output = @output.join("\n")
      expect(output).to include('TGT MIT Credential Cache ticket saved to')
      expect(output).not_to include('Kerberos Credential: FORGE_GOLDEN TGT')
    end

    it 'prints golden ticket metadata without secret key material' do
      configure_manual_ticket(action: 'FORGE_GOLDEN')
      mod.datastore['KerberosTicketTrace'] = 'metadata'

      mod.run

      output = @output.join("\n")
      expect(output).to include('# Kerberos Credential: FORGE_GOLDEN TGT')
      expect(output).to include('Server: krbtgt/DEMO.LOCAL@DEMO.LOCAL')
      expect(output).to include('Client: Administrator@DEMO.LOCAL')
      expect(output).to include('Ticket etype: 23 (RC4_HMAC)')
      expect(output).to include('Ticket Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)')
      expect(output).not_to include('767400b2c71afa35a5dca216f2389cd9')
      expect(output).not_to include('Cipher:')
    end

    it 'prints the trace once when verbose output is enabled' do
      configure_manual_ticket(action: 'FORGE_GOLDEN')
      mod.datastore['KerberosTicketTrace'] = 'metadata'
      mod.datastore['VERBOSE'] = true

      mod.run

      expect(@output.join("\n").scan('# Kerberos Credential: FORGE_GOLDEN TGT').length).to eq(1)
    end

    it 'prints a silver ticket without decrypting it in ticket mode' do
      configure_manual_ticket(action: 'FORGE_SILVER', spn: 'cifs/dc.demo.local')
      mod.datastore['KerberosTicketTrace'] = 'ticket'

      mod.run

      output = @output.join("\n")
      expect(output).to include('# Kerberos Credential: FORGE_SILVER TGS')
      expect(output).to include('Server: cifs/dc.demo.local@DEMO.LOCAL')
      expect(output).to include('Cipher:')
      expect(output).not_to include('Decrypted (with key: 767400b2c71afa35a5dca216f2389cd9):')
    end

    it 'decrypts the golden ticket in full mode' do
      configure_manual_ticket(action: 'FORGE_GOLDEN')
      mod.datastore['KerberosTicketTrace'] = 'full'

      mod.run

      output = @output.join("\n")
      expect(output).to include('# Kerberos Credential: FORGE_GOLDEN TGT')
      expect(output).to include('Decrypted (with key: 767400b2c71afa35a5dca216f2389cd9):')
      expect(output).to include('Logon Domain ID: S-1-5-21-1266190811-2419310613-1856291569')
    end

    it 'traces the final modified diamond ticket' do
      configure_remote_ticket(action: 'FORGE_DIAMOND')
      ccache = build_ccache
      tgt_result = double(
        'tgt_result',
        krb_enc_key: { enctype: Rex::Proto::Kerberos::Crypto::Encryption::AES256 },
        as_rep: double('as_rep', ticket: double('ticket')),
        decrypted_part: double('decrypted_part')
      )
      allow(mod).to receive(:send_request_tgt).and_return(tgt_result)
      expect(mod).to receive(:modify_ticket).and_return(ccache)
      allow(Msf::Exploit::Remote::Kerberos::Ticket::Storage).to receive(:store_ccache)

      mod.run

      output = @output.join("\n")
      expect(output).to include('# Kerberos Credential: FORGE_DIAMOND TGT')
      expect(output).to include('Client: Administrator@DEMO.LOCAL')
    end

    it 'traces the final modified sapphire ticket' do
      configure_remote_ticket(action: 'FORGE_SAPPHIRE')
      ccache = build_ccache
      credential = double(
        'credential',
        keyblock: double(
          'keyblock',
          enctype: double('enctype', value: Rex::Proto::Kerberos::Crypto::Encryption::AES256),
          data: double('data', value: 'C' * 32)
        )
      )
      authenticator = double('authenticator')
      allow(authenticator).to receive(:authenticate_via_kdc).and_return({ credential: credential })
      allow(authenticator).to receive(:u2uself).with(credential, impersonate: 'Administrator').and_return([double('tgs_ticket'), double('tgs_auth')])
      allow(mod).to receive(:kerberos_authenticator).and_return(authenticator)
      expect(mod).to receive(:modify_ticket).and_return(ccache)
      allow(Msf::Exploit::Remote::Kerberos::Ticket::Storage).to receive(:store_ccache)

      mod.run

      output = @output.join("\n")
      expect(output).to include('# Kerberos Credential: FORGE_SAPPHIRE TGT')
      expect(output).to include('Client: Administrator@DEMO.LOCAL')
    end
  end

  def configure_manual_ticket(action:, spn: nil)
    mod.datastore['ACTION'] = action
    mod.datastore['DOMAIN'] = 'demo.local'
    mod.datastore['DOMAIN_SID'] = 'S-1-5-21-1266190811-2419310613-1856291569'
    mod.datastore['NTHASH'] = '767400b2c71afa35a5dca216f2389cd9'
    mod.datastore['AES_KEY'] = nil
    mod.datastore['USER'] = 'Administrator'
    mod.datastore['USER_RID'] = 500
    mod.datastore['RPORT'] = ''
    mod.datastore['EXTRA_SIDS'] = 'S-1-18-1'
    mod.datastore['SessionKey'] = 'A' * 16
    mod.datastore['SPN'] = spn if spn
  end

  def configure_remote_ticket(action:)
    mod.datastore['ACTION'] = action
    mod.datastore['DOMAIN'] = 'demo.local'
    mod.datastore['USER'] = 'Administrator'
    mod.datastore['USER_RID'] = 500
    mod.datastore['REQUEST_USER'] = 'requester'
    mod.datastore['REQUEST_PASSWORD'] = 'Password1!'
    mod.datastore['RHOSTS'] = '192.0.2.10'
    mod.datastore['RPORT'] = 88
    mod.datastore['NTHASH'] = nil
    mod.datastore['AES_KEY'] = 'b' * 64
    mod.datastore['EXTRA_SIDS'] = 'S-1-18-1'
    mod.datastore['KerberosTicketTrace'] = 'metadata'
  end

  def build_ccache
    mod.forge_ticket(
      enc_key: ['b' * 64].pack('H*'),
      enc_type: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
      start_time: Time.utc(2026, 1, 1, 0, 0, 0),
      end_time: Time.utc(2026, 1, 2, 0, 0, 0),
      sname: ['krbtgt', 'DEMO.LOCAL'],
      flags: Rex::Proto::Kerberos::Model::TicketFlags.from_flags(mod.tgt_flags),
      domain: 'demo.local',
      username: 'Administrator',
      user_id: 500,
      domain_sid: 'S-1-5-21-1266190811-2419310613-1856291569',
      extra_sids: ['S-1-18-1'],
      session_key: 'B' * 32
    )
  end
end
