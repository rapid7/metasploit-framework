require 'spec_helper'
require 'metasploit/framework/credential_collection'

describe Metasploit::Framework::CredentialCollection do

  describe "#each" do
    subject(:collection) do
      described_class.new(
        username: username,
        password: password,
        user_file: user_file,
      )
    end

    let(:username) { "user" }
    let(:password) { "pass" }
    let(:user_file) { nil }

    specify do
      expect { |b| collection.each(&b) }.to yield_with_args(Metasploit::Framework::Credential)
    end

    context "when given a user_file and password" do
      let(:username) { nil }
      let(:user_file) do
        filename = "foo"
        stub_file = StringIO.new("asdf\njkl\n")
        File.stub(:open).with(filename,/^r/).and_yield stub_file

        filename
      end

      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: "asdf", private: password),
          Metasploit::Framework::Credential.new(public: "jkl", private: password),
        )
      end
    end
  end

end
