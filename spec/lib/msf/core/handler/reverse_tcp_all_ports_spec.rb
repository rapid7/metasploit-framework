require 'spec_helper'

require 'msf/core/handler/reverse_tcp_all_ports'

describe Msf::Handler::ReverseTcpAllPorts do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
