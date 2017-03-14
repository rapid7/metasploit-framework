# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::CredentialCache::Cache do

  subject(:cache) do
    described_class.new
  end

  let(:sample) do
    "\x05\x04\x00\x0c\x00\x01\x00\x08\xff\xff\xff\xff\x00\x00\x00\x00" +
    "\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0a\x44\x45\x4d\x4f" +
    "\x2e\x4c\x4f\x43\x41\x4c\x00\x00\x00\x04\x6a\x75\x61\x6e\x00\x00" +
    "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0a\x44\x45\x4d\x4f\x2e\x4c" +
    "\x4f\x43\x41\x4c\x00\x00\x00\x04\x6a\x75\x61\x6e\x00\x00\x00\x01" +
    "\x00\x00\x00\x02\x00\x00\x00\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43" +
    "\x41\x4c\x00\x00\x00\x06\x6b\x72\x62\x74\x67\x74\x00\x00\x00\x0a" +
    "\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\x00\x17\x00\x00\x00\x10" +
    "\xf5\x39\xcf\x42\x8a\x03\x2d\x97\x5b\x85\x04\x6e\xe7\xce\x67\x55" +
    "\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04" +
    "\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x04\x41\x42\x43\x44\x00\x00\x00\x00"
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::CredentialCache::Cache correctly" do
      client = Rex::Proto::Kerberos::CredentialCache::Principal.new(
          name_type: 1,
          realm: 'DEMO.LOCAL',
          components: ['juan']
      )

      server = Rex::Proto::Kerberos::CredentialCache::Principal.new(
          name_type: 1,
          realm: 'DEMO.LOCAL',
          components: ['krbtgt', 'DEMO.LOCAL']
      )

      key = Rex::Proto::Kerberos::CredentialCache::KeyBlock.new(
          key_type: Rex::Proto::Kerberos::Crypto::RC4_HMAC,
          e_type: 0,
          key_value: "\xf5\x39\xcf\x42\x8a\x03\x2d\x97\x5b\x85\x04\x6e\xe7\xce\x67\x55"
      )

      times = Rex::Proto::Kerberos::CredentialCache::Time.new(
          auth_time: 1,
          start_time: 2,
          end_time: 3,
          renew_till: 4
      )

      credential = Rex::Proto::Kerberos::CredentialCache::Credential.new(
        client: client,
        server: server,
        key: key,
        time: times,
        is_skey: 0,
        tkt_flags: 0x240000,
        addrs: [],
        auth_data: [],
        ticket: "\x41\x42\x43\x44",
        second_ticket: ''
      )

      cache.version = 0x0504
      cache.headers = ["\x00\x08\xff\xff\xff\xff\x00\x00\x00\x00"]
      cache.primary_principal = client
      cache.credentials = [credential]

      expect(cache.encode).to eq(sample)
    end
  end
end
