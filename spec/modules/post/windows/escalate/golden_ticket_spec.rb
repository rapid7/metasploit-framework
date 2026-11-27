# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'post/windows/escalate/golden_ticket' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'post',
      reference_name: 'windows/escalate/golden_ticket'
    )
  end

  describe 'SID option' do
    it 'registers the SID option using the name read by run' do
      expect(mod.options.keys).to include('SID')
      expect(mod.options.keys).not_to include('Domain SID')
    end

    it 'uses a supplied SID without attempting to look it up' do
      domain_sid = 'S-1-5-21-111111111-222222222-333333333'

      allow(mod).to receive(:load_kiwi).and_return(true)
      kiwi = double
      allow(mod).to receive(:client).and_return(double(kiwi: kiwi))
      allow(Metasploit::Framework::Hashes).to receive(:identify_hash).and_return('nt')

      mod.datastore['USER'] = 'Administrator'
      mod.datastore['DOMAIN'] = 'example.test'
      mod.datastore['KRBTGT_HASH'] = 'krbtgt:0123456789abcdef0123456789abcdef'
      mod.datastore['SID'] = domain_sid

      expect(mod).not_to receive(:lookup_domain_sid)
      expect(kiwi).to receive(:golden_ticket_create)
        .with(hash_including(domain_sid: domain_sid))
        .and_return(nil)
      expect(mod).to receive(:fail_with).with(Msf::Module::Failure::Unknown, 'Unable to create ticket')

      mod.run
    end
  end
end
