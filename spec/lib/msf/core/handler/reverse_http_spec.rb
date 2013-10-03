require 'spec_helper'

require 'msf/core/handler/reverse_http'

describe Msf::Handler::ReverseHttp do
  it_should_behave_like 'Metasploit::Model::Module::Handler' do
    let(:handler_module) do
      described_class
    end
  end
end
