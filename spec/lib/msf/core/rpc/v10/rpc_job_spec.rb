# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::RPC::RPC_Job do
  include_context 'Msf::Simple::Framework'

  let(:service) do
    Msf::RPC::Service.new(framework)
  end

  let(:rpc) do
    described_class.new(service)
  end

  let(:cleaned_up) { [] }

  # Runs inline (async = false), so the job stays in the container until stopped
  def start_job(name, ctx = [])
    framework.jobs.start_job(name, ctx, proc {}, proc { cleaned_up << name })
  end

  describe '#rpc_list' do
    it 'returns an empty hash when there are no jobs' do
      expect(rpc.rpc_list).to eq({})
    end

    it 'maps each job ID to its name' do
      first = start_job('Exploit: first')
      second = start_job('Auxiliary: second')

      expect(rpc.rpc_list).to eq({
        first.to_s => 'Exploit: first',
        second.to_s => 'Auxiliary: second'
      })
    end
  end

  describe '#rpc_stop' do
    it 'stops and removes the job' do
      jid = start_job('Exploit: test')

      expect(rpc.rpc_stop(jid)).to eq({ 'result' => 'success' })
      expect(framework.jobs).to be_empty
      expect(cleaned_up).to eq(['Exploit: test'])
    end

    it 'accepts the job ID as a string' do
      jid = start_job('Exploit: test')

      expect(rpc.rpc_stop(jid.to_s)).to eq({ 'result' => 'success' })
      expect(framework.jobs).to be_empty
    end

    it 'raises a 500 error for an unknown job ID' do
      expect { rpc.rpc_stop(1234) }.to raise_error(Msf::RPC::Exception) { |e|
        expect(e.code).to eq(500)
        expect(e.message).to eq('Invalid Job')
      }
    end

    it 'leaves other jobs running' do
      jid = start_job('Exploit: stop me')
      other = start_job('Exploit: keep me')

      rpc.rpc_stop(jid)

      expect(rpc.rpc_list).to eq({ other.to_s => 'Exploit: keep me' })
    end
  end

  describe '#rpc_info' do
    it 'returns the job ID, name and start time' do
      jid = start_job('Exploit: test')
      job = framework.jobs[jid.to_s]

      expect(rpc.rpc_info(jid)).to eq({
        jid: jid,
        name: 'Exploit: test',
        start_time: job.start_time.to_i
      })
    end

    it 'includes the datastore of the module in the job context' do
      mod = double('module', datastore: Msf::DataStore.new.merge!('RHOSTS' => '192.0.2.1'))
      jid = start_job('Exploit: test', [mod])

      expect(rpc.rpc_info(jid)[:datastore]).to eq({ 'RHOSTS' => '192.0.2.1' })
    end

    it 'includes the URI path when the job context serves a resource' do
      mod = double('module', get_resource: '/abc')
      jid = start_job('Exploit: test', [mod])

      info = rpc.rpc_info(jid)
      expect(info[:uripath]).to eq('/abc')
      expect(info).not_to have_key(:datastore)
    end

    it 'raises a 500 error for an unknown job ID' do
      expect { rpc.rpc_info(1234) }.to raise_error(Msf::RPC::Exception) { |e|
        expect(e.code).to eq(500)
        expect(e.message).to eq('Invalid Job')
      }
    end
  end
end
