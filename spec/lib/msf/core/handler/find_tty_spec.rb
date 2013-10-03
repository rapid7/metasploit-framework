require 'spec_helper'

require 'msf/core/handler/find_tty'

describe Msf::Handler::FindTty do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
