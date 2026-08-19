require 'spec_helper'

RSpec.describe 'auxiliary/server/relay/esc8_kerberos' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'server/relay/esc8_kerberos'
    )
  end

  describe '#normalize_relay_identity' do
    it 'passes a DOMAIN\\HOST$ identity through unchanged' do
      expect(mod.send(:normalize_relay_identity, 'AD\\WIN-VICTIM$')).to eq('AD\\WIN-VICTIM$')
    end

    it 'passes a DOMAIN\\user identity through unchanged' do
      expect(mod.send(:normalize_relay_identity, 'AD\\labuser')).to eq('AD\\labuser')
    end

    it 'converts a UPN machine account HOST$@realm to realm\\HOST$' do
      expect(mod.send(:normalize_relay_identity, 'WIN-VICTIM$@ad.example.com')).to eq('ad.example.com\\WIN-VICTIM$')
    end

    it 'converts a UPN user to realm\\user' do
      expect(mod.send(:normalize_relay_identity, 'labuser@ad.example.com')).to eq('ad.example.com\\labuser')
    end

    it 'leaves the trailing $ so AUTO template selection still sees a machine account' do
      normalized = mod.send(:normalize_relay_identity, 'WIN-VICTIM$@ad.example.com')
      expect(normalized.end_with?('$')).to be(true)
    end

    it 'returns a blank identity unchanged' do
      expect(mod.send(:normalize_relay_identity, '')).to eq('')
    end

    it 'only splits on the first @ so a realm keeps any later @' do
      expect(mod.send(:normalize_relay_identity, 'svc$@a@b')).to eq('a@b\\svc$')
    end
  end
end
