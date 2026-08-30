# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/rpc/v10/rpc_module'
require 'msf/core/rpc/v10/rpc_job_status_tracker'

RSpec.describe Msf::RPC::RPC_Module, '#rpc_check' do
  let(:job_status_tracker) { Msf::RPC::RpcJobStatusTracker.new }
  let(:framework) { double('Framework', modules: modules) }
  let(:modules) { double('ModuleManager') }
  let(:rpc) do
    instance = described_class.allocate
    allow(instance).to receive(:framework).and_return(framework)
    allow(instance).to receive(:job_status_tracker).and_return(job_status_tracker)
    instance
  end

  context 'when the target module does not implement a check method' do
    it 'raises Msf::RPC::Exception with the CheckCode::Unsupported message for an exploit' do
      mod = double('ExploitModule', type: 'exploit', has_check?: false)
      allow(modules).to receive(:create).with('exploit/multi/handler').and_return(mod)
      allow(Msf::Simple::Exploit).to receive(:check_simple)

      expect { rpc.rpc_check('exploit', 'multi/handler', {}) }
        .to raise_error(Msf::RPC::Exception, Msf::Exploit::CheckCode::Unsupported.message)
      expect(Msf::Simple::Exploit).not_to have_received(:check_simple)
    end

    it 'raises Msf::RPC::Exception with the CheckCode::Unsupported message for an auxiliary' do
      mod = double('AuxiliaryModule', type: 'auxiliary', has_check?: false)
      allow(modules).to receive(:create).with('auxiliary/scanner/portscan/tcp').and_return(mod)
      allow(Msf::Simple::Auxiliary).to receive(:check_simple)

      expect { rpc.rpc_check('auxiliary', 'scanner/portscan/tcp', {}) }
        .to raise_error(Msf::RPC::Exception, Msf::Exploit::CheckCode::Unsupported.message)
      expect(Msf::Simple::Auxiliary).not_to have_received(:check_simple)
    end
  end

  context 'when the target module implements a check method' do
    shared_examples 'runs check_simple and returns { job_id, uuid }' do |mtype, mname, simple_klass|
      let(:mod) { double('Module', has_check?: true) }

      before do
        allow(modules).to receive(:create).with("#{mtype}/#{mname}").and_return(mod)
        allow(simple_klass).to receive(:check_simple).and_return(['run-uuid', 42])
      end

      it "returns the { job_id, uuid } hash for #{mtype} modules" do
        response = rpc.rpc_check(mtype, mname, {})
        expect(response).to eq('job_id' => 42, 'uuid' => 'run-uuid')
      end

      it "passes the RPC job_status_tracker via the 'JobListener' opts key for #{mtype} modules" do
        rpc.rpc_check(mtype, mname, {})

        expect(simple_klass).to have_received(:check_simple).with(
          mod,
          hash_including('JobListener' => job_status_tracker)
        )
      end
    end

    include_examples 'runs check_simple and returns { job_id, uuid }',
                     'exploit', 'multi/handler', Msf::Simple::Exploit

    include_examples 'runs check_simple and returns { job_id, uuid }',
                     'auxiliary', 'scanner/portscan/tcp', Msf::Simple::Auxiliary

    it 'lets ::NotImplementedError from check_simple propagate as a defensive fallback' do
      # Belt-and-braces: has_check? should have gated this, but if the driver
      # itself decides check is unsupported at runtime we still surface it.
      mod = double('ExploitModule', type: 'exploit', has_check?: true)
      allow(modules).to receive(:create).with('exploit/multi/handler').and_return(mod)
      allow(Msf::Simple::Exploit).to receive(:check_simple)
        .and_raise(::NotImplementedError.new(Msf::Exploit::CheckCode::Unsupported.message))

      expect { rpc.rpc_check('exploit', 'multi/handler', {}) }
        .to raise_error(::NotImplementedError, Msf::Exploit::CheckCode::Unsupported.message)
    end
  end

  context 'when the module type is not supported by rpc_check' do
    # check is only defined for exploit and auxiliary modules. Other types
    # resolve through _find_module (which happily loads a post module) but
    # hit the case-else branch and are rejected. Non-MCP callers rely on
    # this defensive rejection because they may pass any module type.
    it 'raises Msf::RPC::Exception with an "Invalid Module Type" message' do
      mod = double('PostModule', type: 'post', has_check?: true)
      allow(modules).to receive(:create).with('post/multi/gather/env').and_return(mod)

      expect { rpc.rpc_check('post', 'multi/gather/env', {}) }
        .to raise_error(Msf::RPC::Exception, /Invalid Module Type: post/)
    end
  end
end
