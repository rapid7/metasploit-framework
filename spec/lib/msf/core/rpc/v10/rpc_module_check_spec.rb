# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/rpc/v10/rpc_module'
require 'msf/core/rpc/v10/rpc_job_status_tracker'

RSpec.describe Msf::RPC::RPC_Module, '#rpc_check propagates NotImplementedError from check_simple' do
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

  context 'for an exploit module without a check method' do
    it 'lets ::NotImplementedError propagate so the transport layer can surface a 500 with backtrace' do
      mod = double('ExploitModule')
      allow(modules).to receive(:create).with('exploit/multi/handler').and_return(mod)
      allow(mod).to receive(:type).and_return('exploit')

      unsupported_msg = Msf::Exploit::CheckCode::Unsupported.message
      allow(Msf::Simple::Exploit).to receive(:check_simple).and_raise(::NotImplementedError.new(unsupported_msg))

      expect { rpc.rpc_check('exploit', 'multi/handler', {}) }
        .to raise_error(::NotImplementedError, unsupported_msg)
    end
  end

  context 'for an auxiliary module without a check method' do
    it 'lets ::NotImplementedError propagate so the transport layer can surface a 500 with backtrace' do
      mod = double('AuxiliaryModule')
      allow(modules).to receive(:create).with('auxiliary/scanner/portscan/tcp').and_return(mod)
      allow(mod).to receive(:type).and_return('auxiliary')

      unsupported_msg = Msf::Exploit::CheckCode::Unsupported.message
      allow(Msf::Simple::Auxiliary).to receive(:check_simple).and_raise(::NotImplementedError.new(unsupported_msg))

      expect { rpc.rpc_check('auxiliary', 'scanner/portscan/tcp', {}) }
        .to raise_error(::NotImplementedError, unsupported_msg)
    end
  end

  context 'job_listener wiring' do
    it "passes the RPC job_status_tracker via the 'JobListener' opts key for exploit checks" do
      mod = double('ExploitModule')
      allow(modules).to receive(:create).with('exploit/multi/handler').and_return(mod)
      allow(mod).to receive(:type).and_return('exploit')
      allow(Msf::Simple::Exploit).to receive(:check_simple).and_return(['uuid', 1])

      rpc.rpc_check('exploit', 'multi/handler', {})

      expect(Msf::Simple::Exploit).to have_received(:check_simple).with(
        mod,
        hash_including('JobListener' => job_status_tracker)
      )
    end

    it "passes the RPC job_status_tracker via the 'JobListener' opts key for auxiliary checks" do
      mod = double('AuxiliaryModule')
      allow(modules).to receive(:create).with('auxiliary/scanner/portscan/tcp').and_return(mod)
      allow(mod).to receive(:type).and_return('auxiliary')
      allow(Msf::Simple::Auxiliary).to receive(:check_simple).and_return(['uuid', 1])

      rpc.rpc_check('auxiliary', 'scanner/portscan/tcp', {})

      expect(Msf::Simple::Auxiliary).to have_received(:check_simple).with(
        mod,
        hash_including('JobListener' => job_status_tracker)
      )
    end
  end
end
