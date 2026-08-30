# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Msf::RPC::RPC_Console do
  include_context 'Msf::Simple::Framework'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Framework#threads cleaner', verify_cleanup_required: false
  include_context 'wait_for_expect'

  let(:service) do
    Msf::RPC::Service.new(framework)
  end

  let(:rpc) do
    described_class.new(service)
  end

  describe '#rpc_create' do
    let(:console) { rpc.rpc_create({ 'DisableBanner' => true }) }
    let(:console_id) { console['id'] }

    after(:each) do
      rpc.rpc_destroy(console_id)
    end

    it 'returns has an ID' do
      expect(console).to eq({ "id" => "0", "prompt" => "", "busy" => false })
    end

    it 'supports reading and writing to a console' do
      10.times do
        rpc.rpc_write(console_id, "version\n")
        wait_for_expect do
          read_result = rpc.rpc_read(console_id)
          expected_result = {
            "data" => a_string_matching(/Framework: \d+.*\nConsole  : \d+.*\n/),
            "prompt" => a_string_matching(/.* > /),
            "busy" => false
          }
          expect(read_result).to match(expected_result)
        end
      end
    end
  end
end
