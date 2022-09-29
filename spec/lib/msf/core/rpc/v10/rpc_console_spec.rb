# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Msf::RPC::RPC_Console do
  include_context 'Msf::Simple::Framework'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Framework#threads cleaner', verify_cleanup_required: false

  let(:service) do
    Msf::RPC::Service.new(framework)
  end

  let(:rpc) do
    described_class.new(service)
  end

  # Waits until the given expectations are all true. This function executes the given block,
  # and if a failure occurs it will be retried `retry_count` times before finally failing.
  # This is useful to expect against asynchronous/eventually consistent systems.
  #
  # @param retry_count [Integer] The total amount of times to retry the given expectation
  # @param sleep_duration [Float] The total amount of time to sleep before trying again
  def wait_for_expect(retry_count = 40, sleep_duration = 0.1)
    failure_count = 0

    begin
      yield
    rescue RSpec::Expectations::ExpectationNotMetError
      failure_count += 1
      if failure_count < retry_count
        sleep sleep_duration
        retry
      else
        raise
      end
    end
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
