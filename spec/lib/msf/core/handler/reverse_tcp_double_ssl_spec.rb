require 'spec_helper'

require 'msf/core/handler/reverse_tcp_double_ssl'

describe Msf::Handler::ReverseTcpDoubleSSL do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
