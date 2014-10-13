# -*- coding:binary -*-
require 'spec_helper'

require 'rex/ole'

describe Rex::OLE::CLSID do

  let(:sample_clsid) { "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff" }

  subject(:clsid) do
    described_class.new(sample_clsid)
  end

  describe "#initialize" do
    subject(:clsid_class) do
      described_class.allocate
    end

    it "returns the buf value" do
      expect(clsid_class.send(:initialize, sample_clsid)).to eq(sample_clsid)
    end

    context "when buf is nil" do
      it "returns padding" do
        expect(clsid_class.send(:initialize)).to eq("\x00" * 16)
      end
    end
  end

  describe "#pack" do
    it "returns the buf field" do
      expect(clsid.pack).to eq(sample_clsid)
    end
  end

  describe "#to_s" do
    it "returns printable clsid" do
      Rex::OLE::Util.set_endian(Rex::OLE::LITTLE_ENDIAN)
      expect(clsid.to_s).to eq('33221100-5544-7766-8899-aabbccddeeff')
    end

    context "when buf is nil" do
      it "raises NoMethodError" do
        clsid.instance_variable_set(:@buf, nil)
        expect { clsid.to_s }.to raise_error(NoMethodError)
      end
    end

    context "when buf is shorter than 16 bytes" do
      it "raises TypeError" do
        clsid.instance_variable_set(:@buf, '')
        expect { clsid.to_s }.to raise_error(TypeError)
      end
    end
  end
end
