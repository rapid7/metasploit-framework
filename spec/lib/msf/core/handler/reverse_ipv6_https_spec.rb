require 'spec_helper'

require 'msf/core/handler/reverse_ipv6_https'

describe Msf::Handler::ReverseIPv6Https do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
