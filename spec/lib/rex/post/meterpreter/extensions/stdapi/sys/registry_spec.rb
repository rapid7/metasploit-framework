require 'rex/post/meterpreter/extensions/stdapi/sys/registry'

RSpec.describe Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Registry do

  describe '.type2str' do
    subject { described_class.type2str(type) }

    context "with 'REG_BINARY'" do
      let(:type) { 'REG_BINARY' }
      it { is_expected.to eq(3) }
    end
    context "with 'REG_DWORD'" do
      let(:type) { 'REG_DWORD' }
      it { is_expected.to eq(4) }
    end
    context "with 'REG_EXPAND_SZ'" do
      let(:type) { 'REG_EXPAND_SZ' }
      it { is_expected.to eq(2) }
    end
    context "with 'REG_MULTI_SZ'" do
      let(:type) { 'REG_MULTI_SZ' }
      it { is_expected.to eq(7) }
    end
    context "with 'REG_NONE'" do
      let(:type) { 'REG_NONE' }
      it { is_expected.to eq(0) }
    end
    context "with 'REG_SZ'" do
      let(:type) { 'REG_SZ' }
      it { is_expected.to eq(1) }
    end
  end

end
