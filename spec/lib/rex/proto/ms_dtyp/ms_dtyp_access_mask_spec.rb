RSpec.describe Rex::Proto::MsDtyp::MsDtypAccessMask do
  subject(:instance) { described_class.from_sddl_text(sddl_text) }

  describe '.from_sddl_text' do
    it 'raises an exception on invalid flags' do
      expect { described_class.from_sddl_text('XX') }.to raise_error(Rex::Proto::MsDtyp::SDDLParseError, 'unknown ACE access right: XX')
    end

    context 'when the text is FA' do
      let(:sddl_text) { 'FA' }
      subject(:instance) { described_class.from_sddl_text(sddl_text) }

      it 'sets the protocol to 0x1ff' do
        expect(instance.protocol).to eq 0x1ff
      end

      it 'sets the de flag' do
        expect(instance.de).to eq 1
      end

      it 'sets the rc flag' do
        expect(instance.rc).to eq 1
      end

      it 'sets the wd flag' do
        expect(instance.wd).to eq 1
      end

      it 'sets the wo flag' do
        expect(instance.wo).to eq 1
      end

      it 'sets the sy flag' do
        expect(instance.sy).to eq 1
      end

      it 'does not set the ma flag' do
        expect(instance.ma).to eq 0
      end

      it 'does not set the as flag' do
        expect(instance.as).to eq 0
      end
    end

    context 'when the text is KA' do
      let(:sddl_text) { 'KA' }

      it 'sets the protocol to 0x3f' do
        expect(instance.protocol).to eq 0x3f
      end

      it 'sets the de flag' do
        expect(instance.de).to eq 1
      end

      it 'sets the rc flag' do
        expect(instance.rc).to eq 1
      end

      it 'sets the wd flag' do
        expect(instance.wd).to eq 1
      end

      it 'sets the wo flag' do
        expect(instance.wo).to eq 1
      end

      it 'does not set the sy flag' do
        expect(instance.sy).to eq 0
      end

      it 'does not set the ma flag' do
        expect(instance.ma).to eq 0
      end

      it 'does not set the as flag' do
        expect(instance.as).to eq 0
      end
    end

    context 'when the text is 0x00001234' do
      let(:sddl_text) { '0x00001234' }

      it 'sets the protocol to 0x1234' do
        expect(instance.protocol).to eq 0x1234
      end
    end
  end

  describe '#to_sddl_text' do
    context 'when high protocol bits are set' do
      subject(:instance) { described_class.new(protocol: 0x1234) }
      it 'dumps the value in hex' do
        expect(instance.to_sddl_text).to eq "0x00001234"
      end
    end
  end
end