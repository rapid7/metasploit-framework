require 'spec_helper'
require 'rex/post/process'
require 'rex/post/meterpreter/client'

RSpec.describe Rex::Post::Meterpreter::Client do
  subject(:client) { described_class.allocate }

  describe '#async_lease_enabled?' do
    it 'uses the top-level process clock when Rex::Post::Process is loaded' do
      expect(defined?(Rex::Post::Process)).to eq('constant')

      client.async_lease_renewed(30)

      expect(client.async_lease_enabled?).to be(true)
    end

    it 'clears an expired lease' do
      client.async_lease_enabled = true
      client.instance_variable_set(:@async_lease_deadline, ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) - 1)

      expect(client.async_lease_enabled?).to be(false)
      expect(client.async_lease_enabled).to be(false)
    end
  end
end
