# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/rpc/v10/rpc_module'
require 'msf/core/rpc/v10/rpc_job_status_tracker'

RSpec.describe Msf::RPC::RPC_Module, '#rpc_execute returns uuid/job_id for all module types' do
  let(:service) { double('Service') }
  let(:job_status_tracker) { Msf::RPC::RpcJobStatusTracker.new }
  let(:framework) { double('Framework', modules: modules) }
  let(:modules) { double('ModuleManager') }
  let(:rpc) do
    instance = described_class.allocate
    allow(instance).to receive(:framework).and_return(framework)
    allow(instance).to receive(:job_status_tracker).and_return(job_status_tracker)
    instance
  end

  shared_examples 'returns a hash with job_id and uuid' do |mtype, mname, simple_klass, simple_method|
    it "returns { job_id, uuid } for #{mtype} modules" do
      mod = double('Module', uuid: 'mod-uuid', job_id: 99)
      allow(modules).to receive(:create).with("#{mtype}/#{mname}").and_return(mod)
      allow(mod).to receive(:type).and_return(mtype)

      allow(simple_klass).to receive(simple_method).and_return(['run-uuid', 7])

      opts = mtype == 'exploit' ? { 'PAYLOAD' => 'generic/shell_reverse_tcp' } : {}
      response = rpc.rpc_execute(mtype, mname, opts)
      expect(response).to include('job_id', 'uuid')
      expect(response['job_id']).to be_a(Integer)
      expect(response['uuid']).to be_a(String)
      expect(response['uuid']).not_to be_empty
    end
  end

  include_examples 'returns a hash with job_id and uuid',
                   'exploit', 'multi/handler', Msf::Simple::Exploit, :exploit_simple
  include_examples 'returns a hash with job_id and uuid',
                   'auxiliary', 'scanner/portscan/tcp', Msf::Simple::Auxiliary, :run_simple

  context 'for post modules' do
    it 'returns the run uuid produced by the listener (not just mod.uuid)' do
      mod = double('PostModule', uuid: 'mod-uuid', job_id: 99)
      allow(modules).to receive(:create).with('post/multi/general/execute').and_return(mod)
      allow(mod).to receive(:type).and_return('post')
      allow(Msf::Simple::Post).to receive(:run_simple).and_return(['run-uuid-post', 11])

      response = rpc.rpc_execute('post', 'multi/general/execute', {})
      expect(response['uuid']).to eq('run-uuid-post')
      expect(response['job_id']).to eq(11)
    end
  end

  context 'for evasion modules' do
    it 'returns the run uuid produced by the listener (not just mod.uuid)' do
      mod = double('EvasionModule', uuid: 'mod-uuid', job_id: 99)
      allow(modules).to receive(:create).with('evasion/windows/applocker_evasion_msbuild').and_return(mod)
      allow(mod).to receive(:type).and_return('evasion')
      allow(Msf::Simple::Evasion).to receive(:run_simple).and_return(['run-uuid-evasion', 22])

      response = rpc.rpc_execute('evasion', 'windows/applocker_evasion_msbuild', {})
      expect(response['uuid']).to eq('run-uuid-evasion')
      expect(response['job_id']).to eq(22)
    end
  end
end
