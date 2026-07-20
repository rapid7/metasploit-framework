# frozen_string_literal: true

require 'spec_helper'
require 'msf/base/simple/auxiliary'
require 'msf/base/simple/noop_job_listener'

RSpec.describe Msf::Simple::Auxiliary, '#job_run_proc job tracking' do
  let(:run_uuid) { 'aux-run-uuid' }
  let(:job_listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
  let(:events) { double('EventDispatcher', on_module_run: nil, on_module_complete: nil, on_session_module_run: nil) }
  let(:framework) { double('Framework', events: events) }
  let(:mod) do
    double(
      'AuxiliaryModule',
      framework: framework,
      respond_to?: true,
      :check_code= => nil,
      :last_vuln_attempt= => nil,
      setup: nil,
      cleanup: nil,
      report_failure: nil,
      :error= => nil,
      :fail_reason= => nil,
      :fail_detail= => nil,
      print_error: nil,
      print_status: nil,
      fail_reason: Msf::Module::Failure::None,
      fail_detail: nil
    )
  end
  let(:ctx) { [mod, run_uuid, job_listener] }

  context 'when the block completes successfully' do
    it 'reports start then completed with the block result' do
      result = 'aux-result'
      described_class.job_run_proc(ctx) { |_m| result }
      expect(job_listener).to have_received(:start).with(run_uuid)
      expect(job_listener).to have_received(:completed).with(run_uuid, result, mod)
      expect(job_listener).not_to have_received(:failed)
    end
  end

  context 'when the block raises a generic exception' do
    it 'reports failed with the exception and propagates' do
      err = RuntimeError.new('boom')
      described_class.job_run_proc(ctx) { |_m| raise err }
      expect(job_listener).to have_received(:start).with(run_uuid)
      expect(job_listener).to have_received(:failed).with(run_uuid, err, mod)
      expect(job_listener).not_to have_received(:completed)
    end
  end

  context 'when the block raises Msf::Auxiliary::Complete' do
    it 'is reported via failed (mirrors existing aux behavior) then is swallowed' do
      described_class.job_run_proc(ctx) { |_m| raise Msf::Auxiliary::Complete }
      expect(job_listener).to have_received(:failed).with(run_uuid, kind_of(Msf::Auxiliary::Complete), mod)
    end
  end
end

RSpec.describe Msf::Simple::Auxiliary, 'job_listener keyword signature' do
  it '.run_simple accepts a job_listener kwarg' do
    expect(described_class.method(:run_simple).parameters).to include(%i[key job_listener])
  end

  it '.check_simple accepts a job_listener kwarg' do
    expect(described_class.method(:check_simple).parameters).to include(%i[key job_listener])
  end

  it 'the instance-level run_simple accepts a job_listener kwarg' do
    expect(described_class.instance_method(:run_simple).parameters).to include(%i[key job_listener])
  end

  it 'the instance-level run_simple forwards job_listener: to the class method' do
    mod = Class.new { include Msf::Simple::Auxiliary }.new
    listener = double('JobListener')
    expect(described_class).to receive(:run_simple).with(mod, { opts: 1 }, job_listener: listener)
    mod.run_simple({ opts: 1 }, job_listener: listener)
  end
end
