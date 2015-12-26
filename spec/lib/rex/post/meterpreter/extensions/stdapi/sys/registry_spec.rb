require 'rex/post/meterpreter/extensions/stdapi/sys/registry'

RSpec.describe Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Registry do

  describe '.type2str' do
    subject { described_class.type2str(type) }

    context "with 'REG_BINARY'" do
      let(:type) { 'REG_BINARY' }
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
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
=======
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
      it { should eq(3) }
    end
    context "with 'REG_DWORD'" do
      let(:type) { 'REG_DWORD' }
      it { should eq(4) }
    end
    context "with 'REG_EXPAND_SZ'" do
      let(:type) { 'REG_EXPAND_SZ' }
      it { should eq(2) }
    end
    context "with 'REG_MULTI_SZ'" do
      let(:type) { 'REG_MULTI_SZ' }
      it { should eq(7) }
    end
    context "with 'REG_NONE'" do
      let(:type) { 'REG_NONE' }
      it { should eq(0) }
    end
    context "with 'REG_SZ'" do
      let(:type) { 'REG_SZ' }
      it { should eq(1) }
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
    end
  end

end
