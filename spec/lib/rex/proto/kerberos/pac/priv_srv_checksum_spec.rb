# -*- coding:binary -*-
require 'spec_helper'
require 'rex/proto/kerberos/pac/krb5_pac'


RSpec.describe Rex::Proto::Kerberos::Pac::PrivSvrChecksum do

  subject(:priv_svr_checksum) do
    described_class.new
  end

  let(:rsa_md5) { Rex::Proto::Kerberos::Crypto::Checksum::RSA_MD5 }

  let(:rsa_md5_sample) do
    "\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  end

  describe "#encode" do
    context "when RSA-MD5 checksum" do
      it "encodes the PrivSvrChecksum correctly" do
        priv_svr_checksum.checksum = rsa_md5
        expect(priv_svr_checksum.encode).to eq(rsa_md5_sample)
      end
    end
  end

  describe "#read" do
    it "does not break" do
      BinData.trace_reading do
        x = Rex::Proto::Kerberos::Pac::Krb5PacSignatureData.read(rsa_md5_sample)
        pp x.snapshot
        expect(x).to be_a(Rex::Proto::Kerberos::Pac::Krb5PacSignatureData)
      end
    end
  end
end
