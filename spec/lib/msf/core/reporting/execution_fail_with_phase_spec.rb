# frozen_string_literal: true

require 'spec_helper'

# A1: a +fail_with+ raised from inside +mod.setup+ or +mod.cleanup+
# must record its +Mdm::ModuleExecutionError+ row with
# +lifecycle_phase = 'setup'+ / +'cleanup'+, NOT the module-type
# fallback +'run'+ / +'exploit'+ / +'post'+.
#
# The mechanism is +Msf::Reporting::CurrentPhase+: +with_phase_setup+
# / +with_phase_cleanup+ push the phase onto a thread-local before
# yielding, and +Execution.phase_for+ consults it first.
# +Execution.record_failure!+ (the +fail_with+ path) calls
# +phase_for+ from inside the block, so it picks the pushed value.
RSpec.describe 'Msf::Reporting::Execution fail_with phase attribution (A1)' do
  let(:execution) { double('Mdm::ModuleExecution', id: 42, kind: 'run') }
  let(:aux_mod) { double('aux_mod', type: 'auxiliary', refname: 'test/aux') }
  let(:exploit_mod) { double('exploit_mod', type: 'exploit', refname: 'test/exp') }

  before do
    allow(Msf::Reporting::ConnectionPool).to receive(:with_connection).and_yield
  end

  describe 'fail_with inside with_phase_setup' do
    it 'records the error row with lifecycle_phase = setup on an auxiliary module' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'setup',
          failure_reason: 'no-target'
        )
      )

      Msf::Reporting::CurrentExecution.with(execution) do
        Msf::Reporting::Execution.with_phase_setup(aux_mod) do
          Msf::Reporting::Execution.record_failure!(
            aux_mod,
            failure_reason: Msf::Module::Failure::NoTarget,
            message: 'no target in setup'
          )
        end
      end
    end

    it 'records the error row with lifecycle_phase = setup on an exploit module' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(lifecycle_phase: 'setup')
      )

      Msf::Reporting::CurrentExecution.with(execution) do
        Msf::Reporting::Execution.with_phase_setup(exploit_mod) do
          Msf::Reporting::Execution.record_failure!(
            exploit_mod,
            failure_reason: Msf::Module::Failure::BadConfig,
            message: 'bad config in setup'
          )
        end
      end
    end
  end

  describe 'fail_with inside with_phase_cleanup' do
    it 'records the error row with lifecycle_phase = cleanup' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(lifecycle_phase: 'cleanup')
      )

      Msf::Reporting::CurrentExecution.with(execution) do
        Msf::Reporting::Execution.with_phase_cleanup(aux_mod) do
          Msf::Reporting::Execution.record_failure!(
            aux_mod,
            failure_reason: Msf::Module::Failure::Unknown,
            message: 'boom in cleanup'
          )
        end
      end
    end
  end

  describe 'phase attribution on the module-body path (no override)' do
    it 'falls back to the module-type default when no with_phase_* block is active' do
      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(lifecycle_phase: 'run')
      )

      Msf::Reporting::CurrentExecution.with(execution) do
        Msf::Reporting::Execution.record_failure!(
          aux_mod,
          failure_reason: Msf::Module::Failure::Unknown,
          message: 'boom in run'
        )
      end
    end
  end
end
