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
      mod = double('Module', uuid: 'mod-uuid', job_id: 99, run_uuid: 'run-uuid')
      allow(modules).to receive(:create).with("#{mtype}/#{mname}").and_return(mod)
      allow(mod).to receive(:type).and_return(mtype)

      allow(simple_klass).to receive(simple_method)

      opts = mtype == 'exploit' ? { 'PAYLOAD' => 'generic/shell_reverse_tcp' } : {}
      response = rpc.rpc_execute(mtype, mname, opts)
      expect(response).to include('job_id', 'uuid')
      expect(response['job_id']).to eq(99)
      expect(response['uuid']).to eq('run-uuid')
    end

    it "passes the RPC job_status_tracker via the 'JobListener' opts key for #{mtype} modules" do
      mod = double('Module', uuid: 'mod-uuid', job_id: 99, run_uuid: 'run-uuid')
      allow(modules).to receive(:create).with("#{mtype}/#{mname}").and_return(mod)
      allow(mod).to receive(:type).and_return(mtype)
      allow(simple_klass).to receive(simple_method)

      opts = mtype == 'exploit' ? { 'PAYLOAD' => 'generic/shell_reverse_tcp' } : {}
      rpc.rpc_execute(mtype, mname, opts)

      expect(simple_klass).to have_received(simple_method).with(
        mod,
        hash_including('JobListener' => job_status_tracker)
      )
    end
  end

  include_examples 'returns a hash with job_id and uuid',
                   'exploit', 'multi/handler', Msf::Simple::Exploit, :exploit_simple
  include_examples 'returns a hash with job_id and uuid',
                   'auxiliary', 'scanner/portscan/tcp', Msf::Simple::Auxiliary, :run_simple

  context 'for post modules' do
    it 'returns the run uuid recorded on the module (not just mod.uuid)' do
      mod = double('PostModule', uuid: 'mod-uuid', job_id: 11, run_uuid: 'run-uuid-post')
      allow(modules).to receive(:create).with('post/multi/general/execute').and_return(mod)
      allow(mod).to receive(:type).and_return('post')
      allow(Msf::Simple::Post).to receive(:run_simple)

      response = rpc.rpc_execute('post', 'multi/general/execute', {})
      expect(response['uuid']).to eq('run-uuid-post')
      expect(response['job_id']).to eq(11)
    end

    it "passes the RPC job_status_tracker via the 'JobListener' opts key" do
      mod = double('PostModule', uuid: 'mod-uuid', job_id: 11, run_uuid: 'run-uuid-post')
      allow(modules).to receive(:create).with('post/multi/general/execute').and_return(mod)
      allow(mod).to receive(:type).and_return('post')
      allow(Msf::Simple::Post).to receive(:run_simple)

      rpc.rpc_execute('post', 'multi/general/execute', {})

      expect(Msf::Simple::Post).to have_received(:run_simple).with(
        mod,
        hash_including('JobListener' => job_status_tracker)
      )
    end
  end

  context 'for evasion modules' do
    it 'returns the run uuid recorded on the module (not just mod.uuid)' do
      mod = double('EvasionModule', uuid: 'mod-uuid', job_id: 22, run_uuid: 'run-uuid-evasion')
      allow(modules).to receive(:create).with('evasion/windows/applocker_evasion_msbuild').and_return(mod)
      allow(mod).to receive(:type).and_return('evasion')
      allow(Msf::Simple::Evasion).to receive(:run_simple)

      response = rpc.rpc_execute('evasion', 'windows/applocker_evasion_msbuild', {})
      expect(response['uuid']).to eq('run-uuid-evasion')
      expect(response['job_id']).to eq(22)
    end

    it "passes the RPC job_status_tracker via the 'JobListener' opts key" do
      mod = double('EvasionModule', uuid: 'mod-uuid', job_id: 22, run_uuid: 'run-uuid-evasion')
      allow(modules).to receive(:create).with('evasion/windows/applocker_evasion_msbuild').and_return(mod)
      allow(mod).to receive(:type).and_return('evasion')
      allow(Msf::Simple::Evasion).to receive(:run_simple)

      rpc.rpc_execute('evasion', 'windows/applocker_evasion_msbuild', {})

      expect(Msf::Simple::Evasion).to have_received(:run_simple).with(
        mod,
        hash_including('JobListener' => job_status_tracker)
      )
    end
  end

  context 'when run_uuid is not set on the module' do
    it 'returns nil for the uuid field' do
      mod = double('PostModule', uuid: 'mod-uuid', job_id: 11, run_uuid: nil)
      allow(modules).to receive(:create).with('post/multi/general/execute').and_return(mod)
      allow(mod).to receive(:type).and_return('post')
      allow(Msf::Simple::Post).to receive(:run_simple)

      response = rpc.rpc_execute('post', 'multi/general/execute', {})
      expect(response['uuid']).to be_nil
    end
  end

  context 'structural options validation (defence-in-depth for non-MCP callers)' do
    it 'accepts a well-formed options hash with scalar values' do
      mod = double('Module', uuid: 'u', job_id: 1, run_uuid: 'r', type: 'auxiliary')
      allow(modules).to receive(:create).with('auxiliary/scanner/portscan/tcp').and_return(mod)
      allow(Msf::Simple::Auxiliary).to receive(:run_simple)

      opts = { 'RHOSTS' => '192.0.2.1', 'RPORT' => 445, 'VERBOSE' => true, 'TIMEOUT' => 3.5, 'NOTES' => nil }
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', opts) }.not_to raise_error
    end

    it 'rejects non-Hash options with a 400 error' do
      expect { rpc.rpc_execute('exploit', 'multi/handler', 'not-a-hash') }
        .to raise_error(Msf::RPC::Exception, /Module options must be a Hash/)
    end

    it 'rejects a nested Hash value' do
      opts = { 'RHOSTS' => { 'nested' => 'value' } }
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', opts) }
        .to raise_error(Msf::RPC::Exception, /must be a scalar/)
    end

    it 'rejects an Array value' do
      opts = { 'RHOSTS' => ['a', 'b'] }
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', opts) }
        .to raise_error(Msf::RPC::Exception, /must be a scalar/)
    end

    it 'rejects a non-String/Symbol key' do
      opts = { 42 => 'x' }
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', opts) }
        .to raise_error(Msf::RPC::Exception, /Invalid module option key type/)
    end

    it 'rejects an oversized key' do
      opts = { ('K' * 200) => 'x' }
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', opts) }
        .to raise_error(Msf::RPC::Exception, /key too long/)
    end

    it 'rejects an oversized String value' do
      opts = { 'BIG' => 'x' * (Msf::RPC::RPC_Module::RPC_MODULE_OPTIONS_VALUE_MAX_BYTES + 1) }
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', opts) }
        .to raise_error(Msf::RPC::Exception, /exceeds .* bytes/)
    end

    it 'rejects an options hash with too many keys' do
      opts = Array.new(Msf::RPC::RPC_Module::RPC_MODULE_OPTIONS_MAX_KEYS + 1) { |i| ["K#{i}", 'v'] }.to_h
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', opts) }
        .to raise_error(Msf::RPC::Exception, /too many keys/)
    end

    it 'rejects nil options with a 400 error' do
      expect { rpc.rpc_execute('auxiliary', 'scanner/portscan/tcp', nil) }
        .to raise_error(Msf::RPC::Exception, /Module options must be a Hash/)
    end
  end
end
