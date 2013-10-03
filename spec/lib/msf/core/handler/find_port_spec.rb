require 'spec_helper'

require 'msf/core/handler/find_port'

describe Msf::Handler::FindPort do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
