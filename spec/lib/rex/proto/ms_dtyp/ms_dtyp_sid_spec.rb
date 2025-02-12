RSpec.describe Rex::Proto::MsDtyp::MsDtypSid do
  describe '.from_sddl_text' do
    let (:domain_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }
    let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

    it 'raises an exception on invalid SIDs' do
      expect { described_class.send(:from_sddl_text, 'S-###', domain_sid: domain_sid) }.to raise_error(RuntimeError)
    end

    it 'parses constant SID strings (AU)' do
      expect(described_class.send(:from_sddl_text, 'AU', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:from_sddl_text, 'AU', domain_sid: domain_sid)).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
    end

    it 'parses constant SID strings (DA)' do
      expect(described_class.send(:from_sddl_text, 'DA', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:from_sddl_text, 'DA', domain_sid: domain_sid)).to eq "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ADMINS}"
    end

    it 'parses constant SID strings (AU, case-insensitive)' do
      expect(described_class.send(:from_sddl_text, 'au', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:from_sddl_text, 'au', domain_sid: domain_sid)).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
    end

    it 'parses constant SID strings (DA, case-insensitive)' do
      expect(described_class.send(:from_sddl_text, 'da', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:from_sddl_text, 'da', domain_sid: domain_sid)).to eq "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ADMINS}"
    end

    it 'parses literal SID strings' do
      expect(described_class.send(:from_sddl_text, dummy_sid, domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:from_sddl_text, dummy_sid, domain_sid: domain_sid)).to eq dummy_sid
    end
  end

  describe '#to_sddl_text' do
    let (:domain_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }
    subject(:instance) { described_class.new("#{domain_sid}-512") }

    context 'when the domain_sid argument is passed' do
      it 'reduces the SID to the short form' do
        expect(instance.to_sddl_text(domain_sid: domain_sid)).to eq 'DA'
      end
    end

    context 'when the domain_sid argument is not passed' do
      it 'does not reduce the SID to the short form' do
        expect(instance.to_sddl_text).to eq instance.to_s
      end
    end
  end
end