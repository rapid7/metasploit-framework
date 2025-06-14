require 'spec_helper'
require 'metasploit/framework/credential_collection'

RSpec.describe Metasploit::Framework::PrivateCredentialCollection do

  subject(:collection) do
    described_class.new(
      nil_passwords: nil_passwords,
      blank_passwords: blank_passwords,
      pass_file: pass_file,
      password: password,
      prepended_creds: prepended_creds,
      additional_privates: additional_privates
    )
  end

  before(:each) do
    # The test suite overrides File.open(...) calls; fall back to the normal behavior for any File.open calls that aren't explicitly mocked
    allow(File).to receive(:open).with(anything).and_call_original
    allow(File).to receive(:open).with(anything, anything).and_call_original
    allow(File).to receive(:open).with(anything, anything, anything).and_call_original
  end

  let(:nil_passwords) { nil }
  let(:blank_passwords) { nil }
  let(:password) { "pass" }
  let(:pass_file) { nil }
  # PrivateCredentialCollection yields `nil` as the username; unlike CredentialCollection
  let(:username) { nil }
  let(:prepended_creds) { [] }
  let(:additional_privates) { [] }

  describe "#each" do
    specify do
      expect { |b| collection.each(&b) }.to yield_with_args(Metasploit::Framework::Credential)
    end

    context "when given a pass_file" do
      let(:password) { nil }
      let(:pass_file) do
        filename = "foo"
        stub_file = StringIO.new("asdf\njkl\n")
        allow(File).to receive(:open).with(filename,/^r/).and_return stub_file

        filename
      end

      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: "asdf"),
          Metasploit::Framework::Credential.new(public: username, private: "jkl"),
        )
      end
    end

    context "when :nil_passwords is true" do
      let(:nil_passwords) { true }
      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: password),
          Metasploit::Framework::Credential.new(public: username, private: nil),
        )
      end
    end

    context "when :blank_passwords is true" do
      let(:blank_passwords) { true }
      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: password),
          Metasploit::Framework::Credential.new(public: username, private: ""),
        )
      end
    end

  end

  describe "#empty?" do
    context "when :password is not set" do
      let(:username) { nil }
      let(:password) { nil }
      specify do
        expect(collection.empty?).to eq true
      end

      context "and :prepended_creds is not empty" do
        let(:prepended_creds) { [ "test" ] }
        specify do
          expect(collection.empty?).to eq false
        end
      end

      context "and :additional_privates is not empty" do
        let(:additional_privates) { [ "test_private" ] }
        specify do
          expect(collection.empty?).to eq false
        end
      end

      context "and :additional_publics is not empty" do
        let(:additional_publics) { [ "test_public" ] }
        specify do
          expect(collection.empty?).to eq true
        end
      end
    end

    context "when :password is set" do
      let(:password) { 'pass' }
      specify do
        expect(collection.empty?).to eq false
      end
    end
  end

  describe "#prepend_cred" do
    specify do
      prep = Metasploit::Framework::Credential.new(public: "foo", private: "bar")
      collection.prepend_cred(prep)
      expect { |b| collection.each(&b) }.to yield_successive_args(
        prep,
        Metasploit::Framework::Credential.new(public: username, private: password),
      )
    end
  end

end
