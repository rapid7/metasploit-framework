require 'spec_helper'
require 'metasploit/framework/credential_collection'

describe Metasploit::Framework::CredentialCollection do

  describe "#each" do
    subject(:collection) do
      described_class.new(
        username: "user",
        password: "pass",
      )
    end
    specify do
      expect { |b| collection.each(&b) }.to yield_with_args(Metasploit::Framework::Credential)
    end
  end

end
