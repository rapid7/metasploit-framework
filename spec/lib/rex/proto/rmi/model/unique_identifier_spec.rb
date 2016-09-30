# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'
require 'rex/java'

RSpec.describe Rex::Proto::Rmi::Model::UniqueIdentifier do

  subject(:uid) do
    described_class.new
  end

  let(:uid_raw) do
    "\xd2\x4f\xdf\x47\x00\x00\x01\x49\xb5\xe4\x92\x78\x80\x15"
  end

  let(:uid_raw_io) { StringIO.new(uid_raw) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::UniqueIdentifier decoded" do
      expect(uid.decode(uid_raw_io)).to eq(uid)
    end

    it "decodes number correctly" do
      uid.decode(uid_raw_io)
      expect(uid.number).to eq(-766517433)
    end

    it "decodes time correctly" do
      uid.decode(uid_raw_io)
      expect(uid.time).to eq(1416095896184)
    end

    it "decodes count correctly" do
      uid.decode(uid_raw_io)
      expect(uid.count).to eq(-32747)
    end
  end

  describe "#encode" do
    it "re-encodes a ReturnData stream correctly" do
      uid.decode(uid_raw_io)
      expect(uid.encode).to eq(uid_raw)
    end
  end
end
