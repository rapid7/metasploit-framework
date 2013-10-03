require 'spec_helper'

require 'msf/core/handler/find_shell'

describe Msf::Handler::FindShell do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
