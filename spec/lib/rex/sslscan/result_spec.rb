# -*- coding:binary -*-
require 'rex/sslscan/result'

RSpec.describe Rex::SSLScan::Result do

  subject{Rex::SSLScan::Result.new}

      it { is_expected.to respond_to :accepted }
      it { is_expected.to respond_to :cert }
      it { is_expected.to respond_to :ciphers }
      it { is_expected.to respond_to :rejected }
      it { is_expected.to respond_to :sslv2 }
      it { is_expected.to respond_to :sslv3 }
      it { is_expected.to respond_to :standards_compliant? }
      it { is_expected.to respond_to :strong_ciphers }
      it { is_expected.to respond_to :supports_ssl? }
      it { is_expected.to respond_to :supports_sslv2? }
      it { is_expected.to respond_to :supports_sslv3? }
      it { is_expected.to respond_to :supports_tlsv1? }
      it { is_expected.to respond_to :supports_weak_ciphers? }
      it { is_expected.to respond_to :tlsv1 }
      it { is_expected.to respond_to :weak_ciphers }

  context "with no values set" do
    it "should return nil for the cert" do
      expect(subject.cert).to eq nil
    end

    it "should return an empty set for ciphers" do
      expect(subject.ciphers).to be_empty
    end

    it "should return an empty array for accepted" do
      expect(subject.accepted).to eq []
    end

    it "should return an empty array for rejected" do
      expect(subject.rejected).to eq []
    end

    it "should return an empty array for #sslv2" do
      expect(subject.sslv2).to eq []
    end

    it "should return an empty array for #sslv3" do
      expect(subject.sslv3).to eq []
    end

    it "should return an empty array for #tlsv1" do
      expect(subject.tlsv1).to eq []
    end

    it "should return an empty array for #weak_ciphers" do
      expect(subject.weak_ciphers).to eq []
    end

    it "should return an empty array for #strong_ciphers" do
      expect(subject.strong_ciphers).to eq []
    end

    it "should return false for #supports_ssl?" do
      expect(subject.supports_ssl?).to eq false
    end

    it "should return false for #supports_ssl?v2" do
      expect(subject.supports_sslv2?).to eq false
    end

    it "should return false for #supports_sslv3?" do
      expect(subject.supports_sslv3?).to eq false
    end

    it "should return false for #supports_tlsv1?" do
      expect(subject.supports_tlsv1?).to eq false
    end

    it "should return false for #supports_weak_ciphers?" do
      expect(subject.supports_weak_ciphers?).to eq false
    end

    it "should return true for #standards_compliant?" do
      expect(subject.standards_compliant?).to eq true
    end
  end

  context "setting the cert" do
    it "should accept nil" do
      subject.cert = nil
      expect(subject.cert).to eq nil
    end

    it "should accept an X509 cert" do
      cert = OpenSSL::X509::Certificate.new
      subject.cert = cert
      expect(subject.cert).to eq cert
    end

    it "should raise an exception for anything else" do
      expect{subject.cert = "foo"}.to raise_error(ArgumentError)
    end
  end

  context "adding a cipher result" do
    context "should raise an exception if" do
      it "given an invalid SSL version" do
        expect{subject.add_cipher(:ssl3, 'AES256-SHA', 256, :accepted )}.to raise_error(ArgumentError)
      end

      it "given SSL version as a string" do
        expect{subject.add_cipher('sslv3', 'AES256-SHA', 256, :accepted )}.to raise_error(ArgumentError)
      end

      it "given an invalid SSL cipher" do
        expect{subject.add_cipher(:SSLv3, 'FOO256-SHA', 256, :accepted )}.to raise_error(ArgumentError)
      end

      it "given an unsupported cipher for the version" do
        expect{subject.add_cipher(:SSLv3, 'DES-CBC3-MD5', 256, :accepted )}.to raise_error(ArgumentError)
      end

      it "given a non-number for key length" do
        expect{subject.add_cipher(:SSLv3, 'AES256-SHA', "256", :accepted )}.to raise_error(ArgumentError)
      end

      it "given a decimal key length" do
        expect{subject.add_cipher(:SSLv3, 'AES256-SHA', 25.6, :accepted )}.to raise_error(ArgumentError)
      end

      it "given an invalid status" do
        expect{subject.add_cipher(:SSLv3, 'AES256-SHA', 256, :good )}.to raise_error(ArgumentError)
      end

      it "given status as a string" do
        expect{subject.add_cipher(:SSLv3, 'AES256-SHA', 256, "accepted" )}.to raise_error(ArgumentError)
      end
    end
    context "that was accepted" do
      it "should add an SSLv2 cipher result to the SSLv2 Accepted array or generate an SSLv2 exception" do
        begin
          subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :accepted)
          expect(subject.accepted(:SSLv2)).to include({
            :version => :SSLv2,
            :cipher=>"DES-CBC3-MD5",
            :key_length=>168,
            :weak=> false,
            :status => :accepted})
        rescue ArgumentError => e
          expect(e.message).to eq "unknown SSL method `SSLv2'."
        end
      end

      it "should add an SSLv3 cipher result to the SSLv3 Accepted array" do
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
        expect(subject.accepted(:SSLv3)).to include({
          :version => :SSLv3,
          :cipher=>"AES256-SHA",
          :key_length=>256,
          :weak=> false,
          :status => :accepted})
      end

      it "should add an TLSv1 cipher result to the TLSv1 Accepted array" do
        subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
        expect(subject.accepted(:TLSv1)).to include({
          :version => :TLSv1,
          :cipher=>"AES256-SHA",
          :key_length=>256,
          :weak=> false,
          :status => :accepted})
      end

      it "should successfully add multiple entries in a row" do
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
        expect(subject.accepted(:SSLv3)).to include({
          :version => :SSLv3,
          :cipher=>"AES256-SHA",
          :key_length=>256,
          :weak=> false,
          :status => :accepted})
        expect(subject.accepted(:SSLv3)).to include({
          :version => :SSLv3,
          :cipher=>"AES256-SHA",
          :key_length=>256,
          :weak=> false,
          :status => :accepted})
      end

      it "should not add duplicate entries" do
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
        expect(subject.accepted(:SSLv3).count).to eq 1
      end
    end
    context "that was rejected" do
      it "should add an SSLv2 cipher result to the SSLv2 Rejected array or generate an SSLv2 exception" do
        begin
          subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :rejected)
          expect(subject.rejected(:SSLv2)).to include({
            :version => :SSLv2,
            :cipher=>"DES-CBC3-MD5",
            :key_length=>168,
            :weak=> false,
            :status => :rejected})
        rescue ArgumentError => e
          expect(e.message).to eq "unknown SSL method `SSLv2'."
        end
      end

      it "should add an SSLv3 cipher result to the SSLv3 Rejected array" do
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
        expect(subject.rejected(:SSLv3)).to include({
          :version => :SSLv3,
          :cipher=>"AES256-SHA",
          :key_length=>256,
          :weak=> false,
          :status => :rejected})
      end

      it "should add an TLSv1 cipher result to the TLSv1 Rejected array" do
        subject.add_cipher(:TLSv1, "AES256-SHA", 256, :rejected)
        expect(subject.rejected(:TLSv1)).to include({
          :version => :TLSv1,
          :cipher=>"AES256-SHA",
          :key_length=>256,
          :weak=> false,
          :status => :rejected})
      end

      it "should successfully add multiple entries in a row" do
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
        expect(subject.rejected(:SSLv3)).to include({
          :version => :SSLv3,
          :cipher=>"AES256-SHA",
          :key_length=>256,
          :weak=> false,
          :status => :rejected})
        expect(subject.rejected(:SSLv3)).to include({
          :version => :SSLv3,
          :cipher=>"AES128-SHA",
          :key_length=>128,
          :weak=> false,
          :status => :rejected})
      end

      it "should not add duplicate entries" do
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
        expect(subject.rejected(:SSLv3).count).to eq 1
      end
    end
  end

  context "enumerating all accepted ciphers" do
    before(:each) do
      subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
      subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
      subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
    end

    context "with no version selected" do
      it "should return an array of cipher detail hashes" do
        subject.each_accepted do |cipher_details|
          expect(cipher_details).to include(:version, :cipher, :key_length, :status, :weak)
        end
      end

      it "should return all of the accepted cipher details" do
        count = 0
        subject.each_accepted do |cipher_details|
          count = count+1
        end
        expect(count).to eq 3
      end
    end

    context "when specifying one SSL version" do
      it "should raise an exception if not given a symbol" do
        expect{ subject.each_accepted('sslv2')}.to raise_error(ArgumentError)
      end

      it "should raise an exception if given an invalid SSL version" do
        expect{ subject.each_accepted(:TLSv3)}.to raise_error(ArgumentError)
      end

      it "should return only ciphers matching the version" do
        subject.each_accepted(:SSLv3) do |cipher_details|
          expect(cipher_details[:version]).to eq :SSLv3
        end
      end
    end

    context "when specifying multiple SSL Versions in an array" do
      it "should return all versions if no valid versions were supplied" do
        count = 0
        subject.each_accepted([:TLSv3, :TLSv4]) do |cipher_details|
          count = count+1
        end
        expect(count).to eq 3
      end

      it "should return only the ciphers for the specified version" do
        subject.each_accepted([:SSLv3,:TLSv1]) do |cipher_details|
          expect(cipher_details[:version]).not_to eq :SSLv2
        end
      end
    end
  end

  context "enumerating all rejected ciphers" do
    before(:each) do
      subject.add_cipher(:SSLv3, "AES256-SHA", 256, :rejected)
      subject.add_cipher(:TLSv1, "AES256-SHA", 256, :rejected)
      subject.add_cipher(:SSLv3, "AES128-SHA", 128, :rejected)
    end

    context "with no version selected" do
      it "should return an array of cipher detail hashes" do
        subject.each_rejected do |cipher_details|
          expect(cipher_details).to include(:version, :cipher, :key_length, :status, :weak)
        end
      end

      it "should return all of the rejected cipher details" do
        count = 0
        subject.each_rejected do |cipher_details|
          count = count+1
        end
        expect(count).to eq 3
      end
    end

    context "when specifying one SSL version" do
      it "should raise an exception if not given a symbol" do
        expect{ subject.each_rejected('sslv2')}.to raise_error(ArgumentError)
      end

      it "should raise an exception if given an invalid SSL version" do
        expect{ subject.each_rejected(:TLSv3)}.to raise_error(ArgumentError)
      end

      it "should return only ciphers matching the version" do
        subject.each_rejected(:SSLv3) do |cipher_details|
          expect(cipher_details[:version]).to eq :SSLv3
        end
      end
    end

    context "when specifying multiple SSL Versions in an array" do
      it "should return all versions if no valid versions were supplied" do
        count = 0
        subject.each_rejected([:TLSv3, :TLSv4]) do |cipher_details|
          count = count+1
        end
        expect(count).to eq 3
      end

      it "should return only the ciphers for the specified version" do
        subject.each_rejected([:SSLv3,:TLSv1]) do |cipher_details|
          expect(cipher_details[:version]).not_to eq :SSLv2
        end
      end
    end
  end

  context "checking SSL support" do
    context "for SSLv2" do
      it "should return false if there are no accepted ciphers" do
        expect(subject.supports_sslv2?).to eq false
      end
      it "should return true if there are accepted ciphers or raise an SSLv2 exception" do
        begin
          subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :accepted)
          expect(subject.supports_sslv2?).to eq true
        rescue ArgumentError => e
          expect(e.message).to eq "unknown SSL method `SSLv2'."
        end
      end
    end
    context "for SSLv3" do
      it "should return false if there are no accepted ciphers" do
        expect(subject.supports_sslv3?).to eq false
      end
      it "should return true if there are accepted ciphers" do
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
        expect(subject.supports_sslv3?).to eq true
      end
    end
    context "for TLSv1" do
      it "should return false if there are no accepted ciphers" do
        expect(subject.supports_tlsv1?).to eq false
      end
      it "should return true if there are accepted ciphers" do
        subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
        expect(subject.supports_tlsv1?).to eq true
      end
    end
    context "for SSL at large" do
      it "should return false if there are no accepted ciphers" do
        expect(subject.supports_ssl?).to eq false
      end
      it "should return true if there are accepted ciphers" do
        subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
        expect(subject.supports_ssl?).to eq true
      end
    end
  end

  context "checking for weak ciphers" do
    context "when weak ciphers are supported" do
      before(:each) do
        subject.add_cipher(:SSLv3, "EXP-RC4-MD5", 40, :accepted)
        subject.add_cipher(:SSLv3, "DES-CBC-SHA", 56, :accepted)
      end
      it "should return an array of weak ciphers from #weak_ciphers" do
        weak = subject.weak_ciphers
        expect(weak.class).to eq Array
        weak.each do |cipher|
          expect(cipher[:weak]).to eq true
        end
        expect(weak.count).to eq 2
      end

      it "should return true from #supports_weak_ciphers" do
        expect(subject.supports_weak_ciphers?).to eq true
      end
    end

    context "when no weak ciphers are supported" do
      before(:each) do
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
        subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
      end
      it "should return an empty array from #weak_ciphers" do
        expect(subject.weak_ciphers).to eq []
      end

      it "should return false from #supports_weak_ciphers" do
        expect(subject.supports_weak_ciphers?).to eq false
      end
    end
  end

  context "checking for standards compliance" do
    it "should return true if there is no SSL support" do
      expect(subject.standards_compliant?).to eq true
    end

    it "should return false if SSLv2 is supported or raise an SSLv2 exception" do
      begin
        subject.add_cipher(:SSLv2, "DES-CBC3-MD5", 168, :accepted)
        expect(subject.standards_compliant?).to eq false
      rescue ArgumentError => e
        expect(e.message).to eq "unknown SSL method `SSLv2'."
      end
    end

    it "should return false if weak ciphers are supported" do
      subject.add_cipher(:SSLv3, "EXP-RC2-CBC-MD5", 40, :accepted)
      expect(subject.standards_compliant?).to eq false
    end

    it "should return true if SSLv2 and Weak Ciphers are disabled" do
      subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
      subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
      subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
      expect(subject.standards_compliant?).to eq true
    end
  end

  context "when printing the results" do
    context "when OpenSSL is compiled without SSLv2" do
      before(:each) do
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
        subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
        subject.openssl_sslv2 = false
      end
      it "should warn the user" do
        expect(subject.to_s).to include "*** WARNING: Your OS hates freedom! Your OpenSSL libs are compiled without SSLv2 support!"
      end
    end

    context "when we have SSL results" do
      before(:each) do
        subject.add_cipher(:SSLv3, "AES256-SHA", 256, :accepted)
        subject.add_cipher(:TLSv1, "AES256-SHA", 256, :accepted)
        subject.add_cipher(:SSLv3, "AES128-SHA", 128, :accepted)
        subject.add_cipher(:SSLv3, "EXP-RC2-CBC-MD5", 40, :accepted)

        cert = OpenSSL::X509::Certificate.new
        key = OpenSSL::PKey::RSA.new 2048
        cert.version = 2 #
        cert.serial = 1
        cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
        cert.issuer = cert.subject
        cert.public_key = key.public_key
        cert.not_before = Time.now
        cert.not_after = cert.not_before + 2 * 365 * 24 * 60 * 60 # 2

        subject.cert = cert
      end

      it "should contain the certificate" do
        expect(subject.to_s).to include "Issuer: DC=org, DC=ruby-lang, CN=Ruby CA"
        expect(subject.to_s).to include "Subject: DC=org, DC=ruby-lang, CN=Ruby CA"
      end

      it "should have a table with our SSL Cipher Results" do
        expect(subject.to_s).to include "Accepted  *     SSLv3        40          EXP-RC2-CBC-MD5"
        expect(subject.to_s).to include "Accepted        SSLv3        128         AES128-SHA"
        expect(subject.to_s).to include "Accepted        SSLv3        256         AES256-SHA"
        expect(subject.to_s).to include "Accepted        TLSv1        256         AES256-SHA"
      end
    end

    it "should return an appropriate message when SSL is not supported" do
      expect(subject).to receive(:supports_ssl?).and_return(false)
      expect(subject.to_s).to eq "Server does not appear to support SSL on this port!"
    end


  end

end
