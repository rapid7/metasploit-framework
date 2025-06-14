RSpec.describe Rex::Proto::MsDtyp::MsDtypAce do
  let (:domain_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

  describe '.from_sddl_text' do
    it 'raises an exception on invalid ACEs' do
      expect { described_class.from_sddl_text('', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'too few ACE fields')
      expect { described_class.from_sddl_text(';;;;', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'too few ACE fields')
      expect { described_class.from_sddl_text(';;;;;', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'unknown ACE type: ')
      expect { described_class.from_sddl_text(';;;;;;;', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'too many ACE fields')
    end

    context 'when parsing the ACE type' do
      it 'raises an exception on an invalid type' do
        expect { described_class.from_sddl_text('X;;;;;', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'unknown ACE type: X')
      end

      it 'sets the type correctly for A' do
        expect(described_class.from_sddl_text('A;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      end

      it 'sets the type correctly for A (case-insensitive)' do
        expect(described_class.from_sddl_text('a;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      end

      it 'sets the type correctly for D' do
        expect(described_class.from_sddl_text('D;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_ACE_TYPE
      end

      it 'sets the type correctly for OA' do
        expect(described_class.from_sddl_text('OA;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
      end

      it 'sets the type correctly for OD' do
        expect(described_class.from_sddl_text('OD;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_OBJECT_ACE_TYPE
      end

      it 'sets the type correctly for AU' do
        expect(described_class.from_sddl_text('AU;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_ACE_TYPE
      end

      it 'sets the type correctly for OU' do
        expect(described_class.from_sddl_text('OU;;;;;', domain_sid: domain_sid).header.ace_type).to eq Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE
      end
    end

    context 'when parsing the ACE flags' do
      it 'raises an exception on invalid flags' do
        expect { described_class.from_sddl_text('A;XX;;;;', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'unknown ACE flag: XX')
      end

      it 'sets no flags by default' do
        expect(described_class.from_sddl_text('A;;;;;', domain_sid: domain_sid).header.ace_flags.snapshot.values.sum).to eq 0
      end

      it 'sets the flag correctly for CI' do
        expect(described_class.from_sddl_text('A;CI;;;;', domain_sid: domain_sid).header.ace_flags.container_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for CI (case-insensitive)' do
        expect(described_class.from_sddl_text('A;ci;;;;', domain_sid: domain_sid).header.ace_flags.container_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for OI' do
        expect(described_class.from_sddl_text('A;OI;;;;', domain_sid: domain_sid).header.ace_flags.object_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for NP' do
        expect(described_class.from_sddl_text('A;NP;;;;', domain_sid: domain_sid).header.ace_flags.no_propagate_inherit_ace).to eq 1
      end

      it 'sets the flag correctly for IO' do
        expect(described_class.from_sddl_text('A;IO;;;;', domain_sid: domain_sid).header.ace_flags.inherit_only_ace).to eq 1
      end

      it 'sets the flag correctly for ID' do
        expect(described_class.from_sddl_text('A;ID;;;;', domain_sid: domain_sid).header.ace_flags.inherited_ace).to eq 1
      end

      it 'sets the flag correctly for SA' do
        expect(described_class.from_sddl_text('A;SA;;;;', domain_sid: domain_sid).header.ace_flags.successful_access_ace_flag).to eq 1
      end

      it 'sets the flag correctly for FA' do
        expect(described_class.from_sddl_text('A;FA;;;;', domain_sid: domain_sid).header.ace_flags.failed_access_ace_flag).to eq 1
      end

      it 'sets the flag correctly for CR' do
        expect(described_class.from_sddl_text('A;CR;;;;', domain_sid: domain_sid).header.ace_flags.critical_ace_flag).to eq 1
      end
    end

    context 'when parsing the ACE rights' do
      it 'raises an exception on invalid rights' do
        expect { described_class.from_sddl_text('A;;XX;;;', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'unknown ACE access right: XX')
      end

      it 'sets no rights by default' do
        expect(described_class.from_sddl_text('A;;;;;', domain_sid: domain_sid).body.access_mask).to eq Rex::Proto::MsDtyp::MsDtypAccessMask::NONE
      end

      %w[ GA GR GW GX ].each do |right|
        it "sets the rights correctly for #{right}" do
          expect(described_class.from_sddl_text("A;;#{right};;;", domain_sid: domain_sid).body.access_mask.send(right.downcase)).to eq 1
        end
      end

      it 'sets the rights correctly for FA' do
        expect(described_class.from_sddl_text('A;;FA;;;', domain_sid: domain_sid).body.access_mask.protocol).to eq 0x1ff
        expect(described_class.from_sddl_text('A;;FA;;;', domain_sid: domain_sid).body.access_mask.de).to eq 1
        expect(described_class.from_sddl_text('A;;FA;;;', domain_sid: domain_sid).body.access_mask.rc).to eq 1
        expect(described_class.from_sddl_text('A;;FA;;;', domain_sid: domain_sid).body.access_mask.wd).to eq 1
        expect(described_class.from_sddl_text('A;;FA;;;', domain_sid: domain_sid).body.access_mask.wo).to eq 1
        expect(described_class.from_sddl_text('A;;FA;;;', domain_sid: domain_sid).body.access_mask.sy).to eq 1
      end

      it 'sets the rights correctly for KA' do
        expect(described_class.from_sddl_text('A;;KA;;;', domain_sid: domain_sid).body.access_mask.protocol).to eq 0x3f
        expect(described_class.from_sddl_text('A;;KA;;;', domain_sid: domain_sid).body.access_mask.de).to eq 1
        expect(described_class.from_sddl_text('A;;KA;;;', domain_sid: domain_sid).body.access_mask.rc).to eq 1
        expect(described_class.from_sddl_text('A;;KA;;;', domain_sid: domain_sid).body.access_mask.wd).to eq 1
        expect(described_class.from_sddl_text('A;;KA;;;', domain_sid: domain_sid).body.access_mask.wo).to eq 1
      end
    end

    context 'when parsing the ACE object GUID' do
      let (:dummy_guid) { SecureRandom.uuid }

      it 'raises an exception when the ACE type is incompatible' do
        expect { described_class.from_sddl_text("A;;;#{dummy_guid};;", domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets no object GUID by default' do
        expect(described_class.from_sddl_text("OA;;;;;", domain_sid: domain_sid).body.flags.ace_object_type_present).to eq 0
        expect(described_class.from_sddl_text("OA;;;;;", domain_sid: domain_sid).body.object_type).to eq '00000000-0000-0000-0000-000000000000'
      end

      it 'sets the object type' do
        expect(described_class.from_sddl_text("OA;;;#{dummy_guid};;", domain_sid: domain_sid).body.flags.ace_object_type_present).to eq 1
        expect(described_class.from_sddl_text("OA;;;#{dummy_guid};;", domain_sid: domain_sid).body.object_type).to eq dummy_guid
      end
    end

    context 'when parsing the ACE inherited object GUID' do
      let (:dummy_guid) { SecureRandom.uuid }

      it 'raises an exception when the ACE type is incompatible' do
        expect { described_class.from_sddl_text("A;;;;#{dummy_guid};", domain_sid: domain_sid) }.to raise_error(RuntimeError)
      end

      it 'sets no inherited object GUID by default' do
        expect(described_class.from_sddl_text("OA;;;;;", domain_sid: domain_sid).body.flags.ace_inherited_object_type_present).to eq 0
        expect(described_class.from_sddl_text("OA;;;;;", domain_sid: domain_sid).body.inherited_object_type).to eq '00000000-0000-0000-0000-000000000000'
      end

      it 'sets the inherited object type' do
        expect(described_class.from_sddl_text("OA;;;;#{dummy_guid};", domain_sid: domain_sid).body.flags.ace_inherited_object_type_present).to eq 1
        expect(described_class.from_sddl_text("OA;;;;#{dummy_guid};", domain_sid: domain_sid).body.inherited_object_type).to eq dummy_guid
      end
    end

    context 'when parsing the ACE SID' do
      let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

      it 'calls .from_sddl_text' do
        expect(Rex::Proto::MsDtyp::MsDtypSid).to receive(:from_sddl_text).with(dummy_sid, domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text("A;;;;;#{dummy_sid}", domain_sid: domain_sid).body.sid).to eq dummy_sid
      end
    end
  end

  describe '#to_sddl_text' do
    subject(:instance) { described_class.new(header: { ace_type: ace_type, ace_flags: ace_flags }) }
    let(:sddl_tokens) { instance.to_sddl_text(domain_sid: domain_sid).split(';') }
    let(:ace_type) { Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE }
    let(:ace_flags) { { } }

    context 'when type is ACCESS_ALLOWED_ACE_TYPE' do
      let(:ace_type) { Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE }

      it 'sets the first token to A' do
        expect(sddl_tokens[0]).to eq 'A'
      end
    end

    context 'when type is ACCESS_DENIED_ACE_TYPE' do
      let(:ace_type) { Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_ACE_TYPE }

      it 'sets the first token to D' do
        expect(sddl_tokens[0]).to eq 'D'
      end
    end

    context 'when type is ACCESS_ALLOWED_OBJECT_ACE_TYPE' do
      let(:ace_type) { Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE }

      it 'sets the first token to OA' do
        expect(sddl_tokens[0]).to eq 'OA'
      end
    end

    context 'when type is ACCESS_DENIED_OBJECT_ACE_TYPE' do
      let(:ace_type) { Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_OBJECT_ACE_TYPE }

      it 'sets the first token to OD' do
        expect(sddl_tokens[0]).to eq 'OD'
      end
    end

    context 'when type is SYSTEM_AUDIT_ACE_TYPE' do
      let(:ace_type) { Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_ACE_TYPE }

      it 'sets the first token to AU' do
        expect(sddl_tokens[0]).to eq 'AU'
      end
    end

    context 'when type is SYSTEM_AUDIT_OBJECT_ACE_TYPE' do
      let(:ace_type) { Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE }

      it 'sets the first token to OU' do
        expect(sddl_tokens[0]).to eq 'OU'
      end
    end

    context 'when the object_inherit_ace flag is set' do
      let(:ace_flags) { { object_inherit_ace: true } }

      it 'sets the second token to OI' do
        expect(sddl_tokens[1]).to eq 'OI'
      end
    end

    context 'when the container_inherit_ace flag is set' do
      let(:ace_flags) { { container_inherit_ace: true } }

      it 'sets the second token to CI' do
        expect(sddl_tokens[1]).to eq 'CI'
      end
    end

    context 'when the inherit_only_ace flag is set' do
      let(:ace_flags) { { inherit_only_ace: true } }

      it 'sets the second token to IO' do
        expect(sddl_tokens[1]).to eq 'IO'
      end
    end

    context 'when the no_propagate_inherit_ace flag is set' do
      let(:ace_flags) { { no_propagate_inherit_ace: true } }

      it 'sets the second token to NP' do
        expect(sddl_tokens[1]).to eq 'NP'
      end
    end

    context 'when the inherited_ace flag is set' do
      let(:ace_flags) { { inherited_ace: true } }

      it 'sets the second token to ID' do
        expect(sddl_tokens[1]).to eq 'ID'
      end
    end

    context 'when the successful_access_ace_flag is set' do
      let(:ace_flags) { { successful_access_ace_flag: true } }

      it 'sets the second token to SA' do
        expect(sddl_tokens[1]).to eq 'SA'
      end
    end

    context 'when the failed_access_ace_flag is set' do
      let(:ace_flags) { { failed_access_ace_flag: true } }

      it 'sets the second token to FA' do
        expect(sddl_tokens[1]).to eq 'FA'
      end
    end

    context 'when the critical_ace_flag is set' do
      let(:ace_flags) { { critical_ace_flag: true } }

      it 'sets the second token to CR' do
        expect(sddl_tokens[1]).to eq 'CR'
      end
    end

    context 'when no flags are set' do
      let(:ace_flags) { {  } }

      it 'leaves the second token blank' do
        expect(sddl_tokens[1]).to eq ''
      end
    end

    context 'when all flags are set' do
      let(:ace_flags) { {
        object_inherit_ace: true,
        container_inherit_ace: true,
        inherit_only_ace: true,
        no_propagate_inherit_ace: true,
        inherited_ace: true,
        successful_access_ace_flag: true,
        failed_access_ace_flag: true,
        critical_ace_flag: true
       } }
      it 'sets the second token to OICIIONPIDSAFACR' do
        # this order comes from what was observed on Server 2019
        expect(sddl_tokens[1]).to eq 'OICIIONPIDSAFACR'
      end
    end
  end
end