require 'spec_helper'

require 'msf/core/handler/bind_tcp'

describe Msf::Handler::BindTcp do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
