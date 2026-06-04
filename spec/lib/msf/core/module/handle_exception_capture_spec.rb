# frozen_string_literal: true

require 'spec_helper'

# Unhandled exceptions raised during a module run land in
# +module_execution_errors+ via the live +record_error!+ codepath.
# Specs assert against +::Mdm::ModuleExecutionError.create!+ rather
# than stubbing +capture_exception!+ itself, so that thread-local
# context (CurrentExecution + phase resolution) is exercised
# end-to-end.
RSpec.describe 'Msf::Reporting::Execution capture integration' do
  let(:execution) { double('Mdm::ModuleExecution', id: 7, kind: 'run') }
  let(:check_execution) { double('Mdm::ModuleExecution', id: 8, kind: 'check') }

  describe 'Msf::Exploit#handle_exception inside CurrentExecution.with' do
    let(:exploit) do
      mod = Msf::Exploit.allocate
      mod.instance_variable_set(:@fail_reason, Msf::Module::Failure::None)
      mod.instance_variable_set(:@fail_detail, nil)
      mod.instance_variable_set(
        :@framework,
        double('framework', events: double('events', on_module_error: nil))
      )
      allow(mod).to receive(:framework).and_return(mod.instance_variable_get(:@framework))
      allow(mod).to receive(:refname).and_return('windows/test')
      allow(mod).to receive(:type).and_return('exploit')
      allow(mod).to receive(:print_error)
      allow(mod).to receive(:report_failure)
      allow(mod).to receive(:interrupt_handler)
      allow(mod).to receive(:elog)
      mod
    end

    it 'records an Mdm::ModuleExecutionError with phase exploit' do
      err = Rex::ConnectionError.new('refused')

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'exploit',
          exception_class: 'Rex::ConnectionError',
          failure_reason: Msf::Exploit::Failure::Unreachable
        )
      )

      Msf::Reporting::CurrentExecution.with(execution) do
        exploit.handle_exception(err)
      end
    end

    it 'records phase check when execution kind is check' do
      err = RuntimeError.new('boom')

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(lifecycle_phase: 'check', exception_class: 'RuntimeError')
      )

      Msf::Reporting::CurrentExecution.with(check_execution) do
        exploit.handle_exception(err)
      end
    end

    it 'does not record Msf::Exploit::Failed (already persisted by fail_with)' do
      err = Msf::Exploit::Failed.new('login failed')
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      Msf::Reporting::CurrentExecution.with(execution) do
        exploit.handle_exception(err)
      end
    end

    it 'does not record an exception that has already been marked' do
      err = StandardError.new('boom')
      Msf::Reporting::Execution.mark_exception_recorded(err)

      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      Msf::Reporting::CurrentExecution.with(execution) do
        exploit.handle_exception(err)
      end
    end

    it 'is a no-op when no execution is active (capture_exception! short-circuits)' do
      err = StandardError.new('boom')
      expect(::Mdm::ModuleExecutionError).not_to receive(:create!)

      exploit.handle_exception(err)
    end
  end

  describe 'Msf::Simple::Auxiliary unhandled exception rescue' do
    let(:mod) do
      framework = double(
        'framework',
        events: double('events', on_module_run: nil, on_module_complete: nil)
      )
      m = double(
        'aux',
        framework: framework,
        refname: 'scanner/test',
        fullname: 'auxiliary/scanner/test',
        type: 'auxiliary',
        cleanup: nil,
        report_failure: nil,
        print_error: nil
      )
      allow(m).to receive(:check_code=)
      allow(m).to receive(:last_vuln_attempt=)
      allow(m).to receive(:respond_to?).and_return(true)
      allow(m).to receive(:setup) { raise StandardError, 'kaboom' }
      allow(m).to receive(:error=)
      allow(m).to receive(:fail_reason=)
      allow(m).to receive(:fail_detail=)
      allow(m).to receive(:fail_reason).and_return(Msf::Module::Failure::Unknown)
      allow(m).to receive(:fail_detail).and_return(nil)
      allow(m).to receive(:error).and_return(StandardError.new('kaboom'))
      m
    end

    it 'persists an Mdm::ModuleExecutionError with phase setup' do
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      allow(Msf::Reporting::Execution).to receive(:finalize!)

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'setup',
          exception_class: 'StandardError'
        )
      )

      listener = Msf::Simple::NoopJobListener.instance
      ctx = [mod, 'uuid', listener, { originating_ui: 'console', kind: 'run' }]
      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
    end
  end

  describe 'Msf::Simple::Post unhandled exception rescue' do
    let(:mod) do
      session = double('session')
      framework = double(
        'framework',
        events: double('events',
                       on_module_run: nil,
                       on_session_module_run: nil,
                       on_module_complete: nil),
        sessions: double('sessions', get: session)
      )
      m = double(
        'post_mod',
        framework: framework,
        refname: 'windows/test',
        fullname: 'post/windows/test',
        type: 'post',
        datastore: { 'SESSION' => 1 },
        cleanup: nil,
        print_error: nil,
        setup: nil
      )
      allow(m).to receive(:run) { raise StandardError, 'boom' }
      allow(m).to receive(:error=)
      allow(m).to receive(:error).and_return(StandardError.new('boom'))
      # No respond_to? override: a pure double already reports +true+ for
      # stubbed methods like +:type+, +:refname+, +:fullname+, which is
      # what +phase_for+ → +module_type_for+ needs to map to 'post'.
      m
    end

    it 'persists an Mdm::ModuleExecutionError with phase post' do
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      allow(Msf::Reporting::Execution).to receive(:finalize!)

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'post',
          exception_class: 'StandardError'
        )
      )

      ctx = [mod, { originating_ui: 'console' }]
      Msf::Simple::Post.send(:job_run_proc, ctx)
    end
  end
end
