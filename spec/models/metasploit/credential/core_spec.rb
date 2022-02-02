require 'spec_helper'

RSpec.describe Metasploit::Credential::Core do
  it_should_behave_like 'Metasploit::Credential::Core::ToCredential'
end
