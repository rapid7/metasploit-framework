# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Reporting::Execution do
  let(:execution) { double('Mdm::ModuleExecution', id: 42, kind: 'run') }

  describe '.record_error!' do
    it 'returns nil and does not touch the schema when execution is nil' do
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)
      expect(
        described_class.record_error!(nil, lifecycle_phase: 'run')
      ).to be_nil
    end

    it 'persists an exception with class, message, backtrace, and phase' do
      ex = StandardError.new('boom')
      ex.set_backtrace(['line one', 'line two'])
      now = Time.utc(2026, 6, 1, 12, 0, 0)

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'exploit',
          exception_class: 'StandardError',
          message: 'boom',
          backtrace: "line one\nline two",
          failure_reason: nil,
          occurred_at: now
        )
      )

      described_class.record_error!(
        execution,
        lifecycle_phase: 'exploit',
        exception: ex,
        occurred_at: now
      )
    end

    it 'persists a fail_with-driven failure with exception_class nil' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'run',
          exception_class: nil,
          message: 'Unable to login',
          backtrace: nil,
          failure_reason: 'no-access'
        )
      )

      described_class.record_error!(
        execution,
        lifecycle_phase: 'run',
        failure_reason: 'no-access',
        message: 'Unable to login'
      )
    end

    it 'lets an explicit message override the exception message' do
      ex = RuntimeError.new('raw')
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(message: 'curated', exception_class: 'RuntimeError')
      )

      described_class.record_error!(
        execution,
        lifecycle_phase: 'run',
        exception: ex,
        message: 'curated'
      )
    end

    it 'returns nil and warns when create! raises' do
      ex = StandardError.new('x')
      allow(::Mdm::ModuleExecutionError).to receive(:create!).and_raise(StandardError, 'db down')
      expect(described_class).to receive(:wlog).with(/failed to record ModuleExecutionError for execution #42/)
      expect(
        described_class.record_error!(execution, lifecycle_phase: 'run', exception: ex)
      ).to be_nil
    end
  end

  describe '.truncate_backtrace_for_storage' do
    it 'returns nil for nil input' do
      expect(described_class.truncate_backtrace_for_storage(nil)).to be_nil
    end

    it 'returns nil for an empty array' do
      expect(described_class.truncate_backtrace_for_storage([])).to be_nil
    end

    it 'joins an array backtrace with newlines verbatim when within the cap' do
      expect(
        described_class.truncate_backtrace_for_storage(['a', 'b', 'c'])
      ).to eq("a\nb\nc")
    end

    it 'truncates to max_bytes when above the cap' do
      huge = ['x' * 200_000]
      result = described_class.truncate_backtrace_for_storage(huge, max_bytes: 1024)
      expect(result.bytesize).to eq(1024)
      expect(result).to eq('x' * 1024)
    end

    it 'caps at MAX_BACKTRACE_BYTES by default' do
      huge = ['x' * (described_class::MAX_BACKTRACE_BYTES + 10)]
      result = described_class.truncate_backtrace_for_storage(huge)
      expect(result.bytesize).to eq(described_class::MAX_BACKTRACE_BYTES)
    end
  end

  describe '.phase_for' do
    it 'returns check when the execution is a check, regardless of module type' do
      mod = double('mod', type: 'exploit')
      check_execution = double('execution', kind: 'check')
      expect(described_class.phase_for(mod, execution: check_execution)).to eq('check')
    end

    it 'maps exploits to exploit phase' do
      mod = double('mod', type: 'exploit')
      run_execution = double('execution', kind: 'run')
      expect(described_class.phase_for(mod, execution: run_execution)).to eq('exploit')
    end

    it 'maps post modules to post phase' do
      mod = double('mod', type: 'post')
      run_execution = double('execution', kind: 'run')
      expect(described_class.phase_for(mod, execution: run_execution)).to eq('post')
    end

    it 'maps everything else to run phase' do
      run_execution = double('execution', kind: 'run')
      %w[auxiliary evasion encoder nop payload].each do |module_type|
        mod = double('mod', type: module_type)
        expect(described_class.phase_for(mod, execution: run_execution)).to eq('run')
      end
    end
  end

  describe '.capture_exception!' do
    let(:mod) { double('mod', type: 'auxiliary') }
    let(:exception) { StandardError.new('boom') }

    it 'returns nil and skips persistence when no current execution is set' do
      Msf::Reporting::CurrentExecution.clear
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)
      expect(described_class.capture_exception!(mod, exception)).to be_nil
    end

    it 'records the exception under the derived phase and marks it as recorded' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'run',
          exception_class: 'StandardError'
        )
      )

      Msf::Reporting::CurrentExecution.with(execution) do
        described_class.capture_exception!(mod, exception)
      end
      expect(described_class.exception_recorded?(exception)).to be(true)
    end

    it 'is idempotent: the same exception is only persisted once' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).once
      Msf::Reporting::CurrentExecution.with(execution) do
        described_class.capture_exception!(mod, exception)
        described_class.capture_exception!(mod, exception)
      end
    end

    it 'respects an explicit lifecycle_phase override' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(lifecycle_phase: 'cleanup')
      )
      Msf::Reporting::CurrentExecution.with(execution) do
        described_class.capture_exception!(mod, exception, lifecycle_phase: 'cleanup')
      end
    end
  end

  describe '.record_failure!' do
    let(:mod) { double('mod', type: 'auxiliary') }

    it 'returns nil when no current execution is set' do
      Msf::Reporting::CurrentExecution.clear
      expect(
        described_class.record_failure!(mod, failure_reason: 'no-access', message: 'no')
      ).to be_nil
    end

    it 'persists with exception_class nil and the supplied failure_reason / message' do
      Msf::Reporting::CurrentExecution.with(execution) do
        expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
          hash_including(
            module_execution: execution,
            lifecycle_phase: 'run',
            exception_class: nil,
            failure_reason: 'no-access',
            message: 'Unable'
          )
        )

        described_class.record_failure!(
          mod,
          failure_reason: 'no-access',
          message: 'Unable'
        )
      end
    end
  end
end
