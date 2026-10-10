require 'spec_helper'

RSpec.describe 'auxiliary/admin/ldap/kerberloss' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'admin/ldap/kerberloss'
    )
  end

  describe '#hidden_character' do
    it 'uses explicit source escapes for the supported codepoints' do
      expect(mod.send(:hidden_character, 'U+200C')).to eq("\u{200c}")
      expect(mod.send(:hidden_character, 'U+00AD')).to eq("\u{00ad}")
      expect(mod.send(:hidden_character, 'U+200B')).to eq("\u{200b}")
    end

    it 'rejects an unknown codepoint name' do
      expect { mod.send(:hidden_character, 'U+0041') }.to raise_error(ArgumentError, /Unsupported/)
    end
  end

  describe '#poisoned_spn' do
    it 'appends the selected hidden character without changing the visible SPN' do
      value = mod.send(:poisoned_spn, 'cifs/DC1.kerberloss.test', 'U+200C')
      expect(value).to eq("cifs/DC1.kerberloss.test\u{200c}")
    end
  end

  describe '#visible_value' do
    it 'renders invisible and non-ASCII codepoints explicitly' do
      value = "cifs/DC1\u{200c}\u{00ad}"
      expect(mod.send(:visible_value, value)).to eq('cifs/DC1<U+200C><U+00AD>')
    end

    it 'leaves printable ASCII unchanged' do
      expect(mod.send(:visible_value, 'cifs/DC1.example.test')).to eq('cifs/DC1.example.test')
    end
  end

  describe '#normalize_kerberloss_value' do
    it 'removes all known comparison-ignorable characters' do
      value = "ci\u{034f}fs/DC1\u{2060}"
      expect(mod.send(:normalize_kerberloss_value, value)).to eq('cifs/dc1')
    end

    it 'does not remove U+200B, which is a negative control on Server 2019' do
      expect(mod.send(:normalize_kerberloss_value, "cifs/DC1\u{200b}")).to eq("cifs/dc1\u{200b}")
    end
  end

  describe '#classify_resolution' do
    let(:target_dn) { 'CN=KLTarget,OU=KerberLossLab,DC=kerberloss,DC=test' }
    let(:owner_dn) { 'CN=DC1,OU=Domain Controllers,DC=kerberloss,DC=test' }

    it 'classifies a single target owner as a service hijack' do
      expect(mod.send(:classify_resolution, [], [target_dn], target_dn)).to eq(:hijack)
    end

    it 'classifies multiple normalized owners as a collision and downgrade risk' do
      expect(mod.send(:classify_resolution, [owner_dn], [owner_dn, target_dn], target_dn)).to eq(:collision)
    end

    it 'classifies a write that does not resolve to the target as ineffective' do
      expect(mod.send(:classify_resolution, [], [], target_dn)).to eq(:ineffective)
    end
  end

  describe '#with_temporary_spn' do
    it 'removes the exact probe value even when verification raises' do
      expect(mod).to receive(:add_spn).with('CN=KLTarget,DC=example,DC=test', "msf/probe\u{200c}")
      expect(mod).to receive(:delete_spn).with('CN=KLTarget,DC=example,DC=test', "msf/probe\u{200c}")

      expect do
        mod.send(:with_temporary_spn, 'CN=KLTarget,DC=example,DC=test', "msf/probe\u{200c}") do
          raise Net::LDAP::Error, 'verification failed'
        end
      end.to raise_error(Net::LDAP::Error, /verification failed/)
    end

    it 'does not delete a value that was never added' do
      allow(mod).to receive(:add_spn).and_raise(Net::LDAP::Error, 'write failed')
      expect(mod).not_to receive(:delete_spn)

      expect do
        mod.send(:with_temporary_spn, 'CN=KLTarget,DC=example,DC=test', "msf/probe\u{200c}") { nil }
      end.to raise_error(Net::LDAP::Error, /write failed/)
    end
  end

  describe '#constraint_failure_message' do
    it 'does not claim a constraint violation proves that the DC is patched' do
      message = mod.send(:constraint_failure_message, 'constraintViolation')
      expect(message).to include('patched DC')
      expect(message).to include('insufficient write primitive')
      expect(message).not_to match(/is patched/i)
    end
  end
end
