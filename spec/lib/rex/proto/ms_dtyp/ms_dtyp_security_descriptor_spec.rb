# -*- coding:binary -*-

require 'securerandom'

RSpec.describe Rex::Proto::MsDtyp::MsDtypSecurityDescriptor do
  let (:domain_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}" }
  describe '.from_sddl_text' do
    context 'when parsing an owner SID' do
      let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

      it 'raises an exception when multiple owners are specified' do
        expect { described_class.from_sddl_text('O:AUO:AU', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'raises an exception on invalid constant SID strings' do
        expect { described_class.from_sddl_text('O:XX', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'raises an exception on invalid literal SID strings' do
        expect { described_class.from_sddl_text('O:S-###', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'parses constant SID strings' do
        expect(described_class).to receive(:parse_sddl_sid).with('AU', domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text('O:AU', domain_sid: domain_sid).owner_sid).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
      end

      it 'parses literal SID strings' do
        expect(described_class).to receive(:parse_sddl_sid).with(dummy_sid, domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text("O:#{dummy_sid}", domain_sid: domain_sid).owner_sid).to eq dummy_sid
      end
    end

    context 'when parsing a group SID' do
      let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

      it 'raises an exception when multiple groups are specified' do
        expect { described_class.from_sddl_text('G:AUG:AU', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'raises an exception on invalid constant SID strings' do
        expect { described_class.from_sddl_text('G:XX', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'raises an exception on invalid literal SID strings' do
        expect { described_class.from_sddl_text('G:S-###', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'parses constant SID strings' do
        expect(described_class).to receive(:parse_sddl_sid).with('AU', domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text('G:AU', domain_sid: domain_sid).group_sid).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
      end

      it 'parses literal SID strings' do
        expect(described_class).to receive(:parse_sddl_sid).with(dummy_sid, domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text("G:#{dummy_sid}", domain_sid: domain_sid).group_sid).to eq dummy_sid
      end
    end

    context 'when parsing a DACL' do
      context 'with an empty definitions' do
        let(:instance) { described_class.from_sddl_text('D:', domain_sid: domain_sid) }

        it 'calls .parse_sddl_aces' do
          expect(described_class).to receive(:parse_sddl_aces).with('', domain_sid: domain_sid).and_return([])
          described_class.from_sddl_text('D:', domain_sid: domain_sid)
        end

        it 'sets the ACL when no ACEs are present' do
          expect(instance.dacl).to be_a Rex::Proto::MsDtyp::MsDtypAcl
          expect(instance.dacl.aces).to be_empty
        end

        it 'does not set the P flag' do
          expect(instance.control.pd).to eq 0
        end

        it 'does not set the AI flag' do
          expect(instance.control.di).to eq 0
        end

        it 'does not set the AR flag' do
          expect(instance.control.dc).to eq 0
        end
      end

      it 'raises an exception when multiple values are specified' do
        expect { described_class.from_sddl_text('D:D:', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets the P flag' do
        expect(described_class.from_sddl_text('D:P', domain_sid: domain_sid).control.pd).to eq 1
      end

      it 'sets the AI flag' do
        expect(described_class.from_sddl_text('D:AI', domain_sid: domain_sid).control.di).to eq 1
      end

      it 'sets the AR flag' do
        expect(described_class.from_sddl_text('D:AR', domain_sid: domain_sid).control.dc).to eq 1
      end

      it 'sets a NULL ACL on NO_ACCESS_CONTROL' do
        expect(described_class.from_sddl_text('D:NO_ACCESS_CONTROL', domain_sid: domain_sid).dacl).to be_nil
      end
    end

    context 'when parsing a SACL' do
      context 'with an empty definitions' do
        let(:instance) { described_class.from_sddl_text('S:', domain_sid: domain_sid) }

        it 'calls .parse_sddl_aces' do
          expect(described_class).to receive(:parse_sddl_aces).with('', domain_sid: domain_sid).and_return([])
          described_class.from_sddl_text('S:', domain_sid: domain_sid)
        end

        it 'sets the ACL when no ACEs are present' do
          expect(instance.sacl).to be_a Rex::Proto::MsDtyp::MsDtypAcl
          expect(instance.sacl.aces).to be_empty
        end

        it 'does not set the P flag' do
          expect(instance.control.ps).to eq 0
        end

        it 'does not set the AI flag' do
          expect(instance.control.si).to eq 0
        end

        it 'does not set the AR flag' do
          expect(instance.control.sc).to eq 0
        end
      end

      it 'raises an exception when multiple values are specified' do
        expect { described_class.from_sddl_text('S:S:', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets the P flag' do
        expect(described_class.from_sddl_text('S:P', domain_sid: domain_sid).control.ps).to eq 1
      end

      it 'sets the AI flag' do
        expect(described_class.from_sddl_text('S:AI', domain_sid: domain_sid).control.si).to eq 1
      end

      it 'sets the AR flag' do
        expect(described_class.from_sddl_text('S:AR', domain_sid: domain_sid).control.sc).to eq 1
      end

      it 'sets a NULL ACL on NO_ACCESS_CONTROL' do
        expect(described_class.from_sddl_text('S:NO_ACCESS_CONTROL', domain_sid: domain_sid).sacl).to be_nil
      end
    end
  end

  describe '.parse_sddl_ace' do
    it 'raises an exception on invalid ACEs' do
      expect { described_class.send(:parse_sddl_ace, '', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      expect { described_class.send(:parse_sddl_ace, ';;;;;', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      expect { described_class.send(:parse_sddl_ace, ';;;;;;;', domain_sid: domain_sid) }.to raise_error(RuntimeError)
    end

    context 'when parsing the ACE type' do
      it 'raises an exception on an invalid type' do
        expect { described_class.send(:parse_sddl_ace, 'X;;;;;', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets the type correctly for A' do
        expect(described_class.send(:parse_sddl_ace, 'A;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      end

      it 'sets the type correctly for A (case-insensitive)' do
        expect(described_class.send(:parse_sddl_ace, 'a;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      end

      it 'sets the type correctly for D' do
        expect(described_class.send(:parse_sddl_ace, 'D;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_ACE_TYPE
      end

      it 'sets the type correctly for OA' do
        expect(described_class.send(:parse_sddl_ace, 'OA;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
      end

      it 'sets the type correctly for OD' do
        expect(described_class.send(:parse_sddl_ace, 'OD;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_OBJECT_ACE_TYPE
      end

      it 'sets the type correctly for AU' do
        expect(described_class.send(:parse_sddl_ace, 'AU;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_ACE_TYPE
      end

      it 'sets the type correctly for OU' do
        expect(described_class.send(:parse_sddl_ace, 'OU;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE
      end
    end

    context 'when parsing the ACE flags' do
      it 'raises an exception on invalid flags' do
        expect { described_class.send(:parse_sddl_ace, 'A;XX;;;;', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets no flags by default' do
        expect(described_class.send(:parse_sddl_ace, 'A;;;;;', domain_sid: domain_sid).header.ace_flags.snapshot.values.sum).to eq 0
      end

      it 'sets the flag correctly for CI' do
        expect(described_class.send(:parse_sddl_ace, 'A;CI;;;;', domain_sid: domain_sid).header.ace_flags.container_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for CI (case-insensitive)' do
        expect(described_class.send(:parse_sddl_ace, 'A;ci;;;;', domain_sid: domain_sid).header.ace_flags.container_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for OI' do
        expect(described_class.send(:parse_sddl_ace, 'A;OI;;;;', domain_sid: domain_sid).header.ace_flags.object_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for NP' do
        expect(described_class.send(:parse_sddl_ace, 'A;NP;;;;', domain_sid: domain_sid).header.ace_flags.no_propagate_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for IO' do
        expect(described_class.send(:parse_sddl_ace, 'A;IO;;;;', domain_sid: domain_sid).header.ace_flags.inherit_only_ace).to eq 1
      end

      it 'sets the flag correctly for ID' do
        expect(described_class.send(:parse_sddl_ace, 'A;ID;;;;', domain_sid: domain_sid).header.ace_flags.inherited_ace).to eq 1
      end

      it 'sets the flag correctly for SA' do
        expect(described_class.send(:parse_sddl_ace, 'A;SA;;;;', domain_sid: domain_sid).header.ace_flags.successful_access_ace_flag).to eq 1
      end

      it 'sets the flag correctly for FA' do
        expect(described_class.send(:parse_sddl_ace, 'A;FA;;;;', domain_sid: domain_sid).header.ace_flags.failed_access_ace_flag).to eq 1
      end

      it 'sets the flag correctly for CR' do
        expect(described_class.send(:parse_sddl_ace, 'A;CR;;;;', domain_sid: domain_sid).header.ace_flags.critical_ace_flag).to eq 1
      end
    end

    context 'when parsing the ACE rights' do
      it 'raises an exception on invalid rights' do
        expect { described_class.send(:parse_sddl_ace, 'A;;XX;;;', domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets no rights by default' do
        expect(described_class.send(:parse_sddl_ace, 'A;;;;;', domain_sid: domain_sid).body.access_mask).to eq Rex::Proto::MsDtyp::MsDtypAccessMask::NONE
      end

      %w[ GA GR GW GX ].each do |right|
        it "sets the rights correctly for #{right}" do
          expect(described_class.send(:parse_sddl_ace, "A;;#{right};;;", domain_sid: domain_sid).body.access_mask.send(right.downcase)).to eq 1
        end
      end

      it 'sets the rights correctly for FA' do
        expect(described_class.send(:parse_sddl_ace, 'A;;FA;;;', domain_sid: domain_sid).body.access_mask.protocol).to eq 0x1ff
        expect(described_class.send(:parse_sddl_ace, 'A;;FA;;;', domain_sid: domain_sid).body.access_mask.de).to eq 1
        expect(described_class.send(:parse_sddl_ace, 'A;;FA;;;', domain_sid: domain_sid).body.access_mask.rc).to eq 1
        expect(described_class.send(:parse_sddl_ace, 'A;;FA;;;', domain_sid: domain_sid).body.access_mask.wd).to eq 1
        expect(described_class.send(:parse_sddl_ace, 'A;;FA;;;', domain_sid: domain_sid).body.access_mask.wo).to eq 1
        expect(described_class.send(:parse_sddl_ace, 'A;;FA;;;', domain_sid: domain_sid).body.access_mask.sy).to eq 1
      end

      it 'sets the rights correctly for KA' do
        expect(described_class.send(:parse_sddl_ace, 'A;;KA;;;', domain_sid: domain_sid).body.access_mask.protocol).to eq 0x3f
        expect(described_class.send(:parse_sddl_ace, 'A;;KA;;;', domain_sid: domain_sid).body.access_mask.de).to eq 1
        expect(described_class.send(:parse_sddl_ace, 'A;;KA;;;', domain_sid: domain_sid).body.access_mask.rc).to eq 1
        expect(described_class.send(:parse_sddl_ace, 'A;;KA;;;', domain_sid: domain_sid).body.access_mask.wd).to eq 1
        expect(described_class.send(:parse_sddl_ace, 'A;;KA;;;', domain_sid: domain_sid).body.access_mask.wo).to eq 1
      end
    end

    context 'when parsing the ACE object GUID' do
      let (:dummy_guid) { SecureRandom.uuid }

      it 'raises an exception when the ACE type is incompatible' do
        expect { described_class.send(:parse_sddl_ace, "A;;;#{dummy_guid};;", domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets no object GUID by default' do
        expect(described_class.send(:parse_sddl_ace, "OA;;;;;", domain_sid: domain_sid).body.flags.ace_object_type_present).to eq 0
        expect(described_class.send(:parse_sddl_ace, "OA;;;;;", domain_sid: domain_sid).body.object_type).to eq '00000000-0000-0000-0000-000000000000'
      end

      it 'sets the object type' do
        expect(described_class.send(:parse_sddl_ace, "OA;;;#{dummy_guid};;", domain_sid: domain_sid).body.flags.ace_object_type_present).to eq 1
        expect(described_class.send(:parse_sddl_ace, "OA;;;#{dummy_guid};;", domain_sid: domain_sid).body.object_type).to eq dummy_guid
      end
    end

    context 'when parsing the ACE inherited object GUID' do
      let (:dummy_guid) { SecureRandom.uuid }

      it 'raises an exception when the ACE type is incompatible' do
        expect { described_class.send(:parse_sddl_ace, "A;;;;#{dummy_guid};", domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets no inherited object GUID by default' do
        expect(described_class.send(:parse_sddl_ace, "OA;;;;;", domain_sid: domain_sid).body.flags.ace_inherited_object_type_present).to eq 0
        expect(described_class.send(:parse_sddl_ace, "OA;;;;;", domain_sid: domain_sid).body.inherited_object_type).to eq '00000000-0000-0000-0000-000000000000'
      end

      it 'sets the inherited object type' do
        expect(described_class.send(:parse_sddl_ace, "OA;;;;#{dummy_guid};", domain_sid: domain_sid).body.flags.ace_inherited_object_type_present).to eq 1
        expect(described_class.send(:parse_sddl_ace, "OA;;;;#{dummy_guid};", domain_sid: domain_sid).body.inherited_object_type).to eq dummy_guid
      end
    end

    context 'when parsing the ACE SID' do
      let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

      it 'calls .parse_sddl_sid' do
        expect(described_class).to receive(:parse_sddl_sid).with(dummy_sid, domain_sid: domain_sid).and_call_original
        expect(described_class.send(:parse_sddl_ace, "A;;;;;#{dummy_sid}", domain_sid: domain_sid).body.sid).to eq dummy_sid
      end
    end
  end

  describe '.parse_sddl_sid' do
    let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

    it 'raises an exception on invalid SIDs' do
      expect { described_class.send(:parse_sddl_sid, 'S-###', domain_sid: domain_sid) }.to raise_error(RuntimeError)
    end

    it 'parses constant SID strings (AU)' do
      expect(described_class.send(:parse_sddl_sid, 'AU', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:parse_sddl_sid, 'AU', domain_sid: domain_sid)).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
    end

    it 'parses constant SID strings (DA)' do
      expect(described_class.send(:parse_sddl_sid, 'DA', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:parse_sddl_sid, 'DA', domain_sid: domain_sid)).to eq "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ADMINS}"
    end

    it 'parses constant SID strings (AU, case-insensitive)' do
      expect(described_class.send(:parse_sddl_sid, 'au', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:parse_sddl_sid, 'au', domain_sid: domain_sid)).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
    end

    it 'parses constant SID strings (DA, case-insensitive)' do
      expect(described_class.send(:parse_sddl_sid, 'da', domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:parse_sddl_sid, 'da', domain_sid: domain_sid)).to eq "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ADMINS}"
    end

    it 'parses literal SID strings' do
      expect(described_class.send(:parse_sddl_sid, dummy_sid, domain_sid: domain_sid)).to be_a Rex::Proto::MsDtyp::MsDtypSid
      expect(described_class.send(:parse_sddl_sid, dummy_sid, domain_sid: domain_sid)).to eq dummy_sid
    end
  end
end
