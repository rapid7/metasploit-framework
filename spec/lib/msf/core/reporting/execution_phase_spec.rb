# frozen_string_literal: true

require 'spec_helper'

# Phase resolution helpers. Resolution order:
#   1. execution.kind == 'check' -> PHASE_CHECK
#   2. module-type fallback (exploit/post/run)
# +with_phase_setup+ / +with_phase_cleanup+ record errors raised
# inside their block against the active execution with the matching
# explicit lifecycle_phase.
RSpec.describe Msf::Reporting::Execution, '.phase_for / .with_phase_setup / .with_phase_cleanup' do
  let(:execution) { double('Mdm::ModuleExecution', id: 1, kind: 'run') }
  let(:check_execution) { double('Mdm::ModuleExecution', id: 2, kind: 'check') }
  let(:exploit_mod) { double('exploit_mod', type: 'exploit') }
  let(:aux_mod) { double('aux_mod', type: 'auxiliary') }
  let(:post_mod) { double('post_mod', type: 'post') }

  describe '.phase_for' do
    it 'returns PHASE_CHECK when the execution kind is check' do
      expect(described_class.phase_for(exploit_mod, execution: check_execution)).to eq('check')
    end

    it 'returns PHASE_EXPLOIT for an exploit module' do
      expect(described_class.phase_for(exploit_mod, execution: execution)).to eq('exploit')
    end

    it 'returns PHASE_POST for a post module' do
      expect(described_class.phase_for(post_mod, execution: execution)).to eq('post')
    end

    it 'returns PHASE_RUN for any other module type' do
      expect(described_class.phase_for(aux_mod, execution: execution)).to eq('run')
    end

    it 'returns the module-type fallback when execution is nil' do
      expect(described_class.phase_for(exploit_mod, execution: nil)).to eq('exploit')
    end
  end

  describe '.with_phase_setup' do
    it 'returns the block value on the happy path with no DB write' do
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      Msf::Reporting::CurrentExecution.with(execution) do
        result = described_class.with_phase_setup(exploit_mod) { :ok }
        expect(result).to eq(:ok)
      end
    end

    it 'records the exception with lifecycle_phase setup and re-raises' do
      err = StandardError.new('boom')

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'setup',
          exception_class: 'StandardError'
        )
      )

      expect do
        Msf::Reporting::CurrentExecution.with(execution) do
          described_class.with_phase_setup(exploit_mod) { raise err }
        end
      end.to raise_error(StandardError, 'boom')
    end

    it 'is a no-op when no execution is active' do
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      expect do
        described_class.with_phase_setup(exploit_mod) { raise StandardError, 'no exec' }
      end.to raise_error(StandardError)
    end
  end

  describe '.with_phase_cleanup' do
    it 'returns the block value on the happy path with no DB write' do
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      Msf::Reporting::CurrentExecution.with(execution) do
        result = described_class.with_phase_cleanup(exploit_mod) { :ok }
        expect(result).to eq(:ok)
      end
    end

    it 'records the exception with lifecycle_phase cleanup and re-raises' do
      err = StandardError.new('cleanup blew up')

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'cleanup',
          exception_class: 'StandardError'
        )
      )

      expect do
        Msf::Reporting::CurrentExecution.with(execution) do
          described_class.with_phase_cleanup(exploit_mod) { raise err }
        end
      end.to raise_error(StandardError, 'cleanup blew up')
    end

    it 'overrides the module-type fallback even when the execution kind is run' do
      err = StandardError.new('cleanup blew up')

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(lifecycle_phase: 'cleanup')
      )

      expect do
        Msf::Reporting::CurrentExecution.with(execution) do
          described_class.with_phase_cleanup(exploit_mod) { raise err }
        end
      end.to raise_error(StandardError)
    end

    it 'is a no-op when no execution is active' do
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      expect do
        described_class.with_phase_cleanup(exploit_mod) { raise StandardError, 'no exec' }
      end.to raise_error(StandardError)
    end

    it 'deduplicates against an already-recorded exception ivar' do
      err = StandardError.new('already handled')
      Msf::Reporting::Execution.mark_exception_recorded(err)

      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      expect do
        Msf::Reporting::CurrentExecution.with(execution) do
          described_class.with_phase_cleanup(exploit_mod) { raise err }
        end
      end.to raise_error(StandardError)
    end
  end
end
