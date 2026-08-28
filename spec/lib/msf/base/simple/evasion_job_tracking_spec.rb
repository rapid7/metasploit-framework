# frozen_string_literal: true

require 'spec_helper'
require 'msf/base/simple/evasion'
require 'msf/base/simple/noop_job_listener'
require 'msf/core/evasion_driver'

RSpec.describe Msf::EvasionDriver, '#job_run_proc job tracking' do
  let(:run_uuid) { 'evasion-run-uuid' }
  let(:job_listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
  let(:events) { double('EventDispatcher', on_module_run: nil, on_module_complete: nil) }
  let(:framework) { double('Framework', events: events) }
  let(:evasion_mod) { double('EvasionModule', setup: nil, framework: framework, run: 'evasion-output', cleanup: nil) }
  let(:payload) { double('Payload') }
  let(:driver) { described_class.new(framework) }

  before do
    driver.job_listener = job_listener if driver.respond_to?(:job_listener=)
    driver.evasion = evasion_mod
    driver.payload = payload
  end

  context 'when the module runs successfully' do
    it 'reports start then completed' do
      driver.send(:job_run_proc, [evasion_mod, payload, run_uuid, job_listener])
      expect(job_listener).to have_received(:start).with(run_uuid)
      expect(job_listener).to have_received(:completed).with(run_uuid, 'evasion-output', evasion_mod)
      expect(job_listener).not_to have_received(:failed)
    end
  end

  context 'when the module raises' do
    it 'reports failed with the exception' do
      err = RuntimeError.new('evasion-boom')
      allow(evasion_mod).to receive(:run).and_raise(err)
      expect do
        driver.send(:job_run_proc, [evasion_mod, payload, run_uuid, job_listener])
      end.to raise_error(RuntimeError, 'evasion-boom')
      expect(job_listener).to have_received(:failed).with(run_uuid, err, evasion_mod)
    end
  end
end

RSpec.describe Msf::EvasionDriver, '#initialize' do
  let(:framework) { double('Framework') }

  it 'accepts a job_listener keyword argument' do
    listener = double('JobListener')
    driver = described_class.new(framework, job_listener: listener)
    expect(driver.job_listener).to eq(listener)
  end

  it 'defaults to the noop job listener' do
    driver = described_class.new(framework)
    expect(driver.job_listener).to eq(Msf::Simple::NoopJobListener.instance)
  end
end
