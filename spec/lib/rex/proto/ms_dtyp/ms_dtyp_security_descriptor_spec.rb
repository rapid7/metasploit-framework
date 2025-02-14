# -*- coding:binary -*-

require 'securerandom'

RSpec.describe Rex::Proto::MsDtyp::MsDtypSecurityDescriptor do
  let (:domain_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}" }
  describe '.from_sddl_text' do
    context 'when parsing an owner SID' do
      let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

      it 'raises an exception when multiple owners are specified' do
        expect { described_class.from_sddl_text('O:AUO:AU', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'extra owner SID')
      end

      it 'raises an exception on invalid constant SID strings' do
        expect { described_class.from_sddl_text('O:XX', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'invalid SID string: XX')
      end

      it 'raises an exception on invalid literal SID strings' do
        expect { described_class.from_sddl_text('O:S-###', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'invalid SID string: S-###')
      end

      it 'parses constant SID strings' do
        expect(Rex::Proto::MsDtyp::MsDtypSid).to receive(:from_sddl_text).with('AU', domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text('O:AU', domain_sid: domain_sid).owner_sid).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
      end

      it 'parses literal SID strings' do
        expect(Rex::Proto::MsDtyp::MsDtypSid).to receive(:from_sddl_text).with(dummy_sid, domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text("O:#{dummy_sid}", domain_sid: domain_sid).owner_sid).to eq dummy_sid
      end
    end

    context 'when parsing a group SID' do
      let (:dummy_sid) { "S-1-5-21-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(0xf00000..0xffffffff)}-#{rand(100..999)}" }

      it 'raises an exception when multiple groups are specified' do
        expect { described_class.from_sddl_text('G:AUG:AU', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'extra group SID')
      end

      it 'raises an exception on invalid constant SID strings' do
        expect { described_class.from_sddl_text('G:XX', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'invalid SID string: XX')
      end

      it 'raises an exception on invalid literal SID strings' do
        expect { described_class.from_sddl_text('G:S-###', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'invalid SID string: S-###')
      end

      it 'parses constant SID strings' do
        expect(Rex::Proto::MsDtyp::MsDtypSid).to receive(:from_sddl_text).with('AU', domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text('G:AU', domain_sid: domain_sid).group_sid).to eq Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
      end

      it 'parses literal SID strings' do
        expect(Rex::Proto::MsDtyp::MsDtypSid).to receive(:from_sddl_text).with(dummy_sid, domain_sid: domain_sid).and_call_original
        expect(described_class.from_sddl_text("G:#{dummy_sid}", domain_sid: domain_sid).group_sid).to eq dummy_sid
      end
    end

    context 'when parsing a DACL' do
      context 'with an empty definitions' do
        let(:instance) { described_class.from_sddl_text('D:', domain_sid: domain_sid) }

        it 'calls .aces_from_sddl_text' do
          expect(described_class).to receive(:aces_from_sddl_text).with('', domain_sid: domain_sid).and_return([])
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
        expect { described_class.from_sddl_text('D:D:', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'extra DACL')
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

        it 'calls .aces_from_sddl_text' do
          expect(described_class).to receive(:aces_from_sddl_text).with('', domain_sid: domain_sid).and_return([])
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
        expect { described_class.from_sddl_text('S:S:', domain_sid: domain_sid) }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'extra SACL')
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

  describe '#to_sddl_text' do
    it 'handles a basic owner and group with a simple DACL' do
      sddl_text = 'O:BAG:BUD:PAI(A;;FA;;;BA)'
      packed = ['01000494140000002400000000000000340000000102000000000005200000002002000001020000000000052000000021020000020020000100000000001800FF011F0001020000000000052000000020020000'].pack('H*')
      instance = described_class.read(packed)
      expect(instance.to_sddl_text(domain_sid: domain_sid)).to eq sddl_text
    end

    it 'handles a complex DACL with multiple ACEs' do
      sddl_text = 'O:S-1-5-21-123456789-123456789-123456789-519G:S-1-5-21-123456789-123456789-123456789-512D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICIIO;FA;;;CO)'
      packed = ['010004941400000030000000000000004C00000001050000000000051500000015CD5B0715CD5B0715CD5B070702000001050000000000051500000015CD5B0715CD5B0715CD5B0700020000020048000300000000031800FF011F000102000000000005200000002002000000031400FF011F00010100000000000512000000000B1400FF011F00010100000000000300000000'].pack('H*')
      instance = described_class.read(packed)
      expect(instance.to_sddl_text(domain_sid: domain_sid)).to eq sddl_text
    end

    it 'handles a SACL with auditing' do
      sddl_text = 'O:BAG:SYS:PAI(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
      packed = ['010010A8140000002400000030000000000000000102000000000005200000002002000001010000000000051200000002001C000100000002801400FF010F00010100000000000100000000'].pack('H*')
      instance = described_class.read(packed)
      expect(instance.to_sddl_text(domain_sid: domain_sid)).to eq sddl_text
    end

    it 'handles a complex descriptor with both a DACL and a SACL' do
      sddl_text = 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)S:AI(AU;SA;FA;;;BA)'
      packed = ['0100149C1400000024000000300000005000000001020000000000052000000020020000010100000000000512000000020020000100000002401800FF011F0001020000000000052000000020020000020034000200000000031800FF011F000102000000000005200000002002000000031400FF011F00010100000000000512000000'].pack('H*')
      instance = described_class.read(packed)
      expect(instance.to_sddl_text(domain_sid: domain_sid)).to eq sddl_text
    end

    it 'handles a NULL DACL (everyone denied)' do
      sddl_text = 'O:BAG:BAD:'
      packed = ['010004801400000024000000000000003400000001020000000000052000000020020000010200000000000520000000200200000200080000000000'].pack('H*')
      instance = described_class.read(packed)
      expect(instance.to_sddl_text(domain_sid: domain_sid)).to eq sddl_text
    end

    it 'handles a protected DACL with inheritance disabled' do
      sddl_text = 'O:BAG:BAD:PAI(D;CIIO;FA;;;WD)(A;;FA;;;BA)'
      packed = ['010004941400000024000000000000003400000001020000000000052000000020020000010200000000000520000000200200000200340002000000010A1400FF011F0001010000000000010000000000001800FF011F0001020000000000052000000020020000'].pack('H*')
      instance = described_class.read(packed)
      expect(instance.to_sddl_text(domain_sid: domain_sid)).to eq sddl_text
    end
  end
end
