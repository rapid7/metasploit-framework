# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Msf::RPC::RPC_Core do
  include_context 'Msf::Simple::Framework'

  let(:service) do
    Msf::RPC::Service.new(framework)
  end

  let(:core) do
    Msf::RPC::RPC_Core.new(service)
  end

  describe '#rpc_getg' do
    it 'should show an empty value if the variable is unset' do
      expect(core.rpc_getg('FOO')).to eq({'FOO' => ''})
    end
    it 'should show the correct value if the variable is set' do
      core.rpc_setg('FOO', 'BAR')
      expect(core.rpc_getg('FOO')).to eq({'FOO' => 'BAR'})
    end
  end
end
