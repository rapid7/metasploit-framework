# frozen_string_literal: true

require 'spec_helper'

# Verifies that +Msf::Simple::Auxiliary.run_simple+ and +.check_simple+
# bracket the module call with +Msf::Reporting::Execution.start!+ /
# +.finalize!+ and expose the execution via
# +Msf::Reporting::CurrentExecution+ for the duration of the run.
RSpec.describe 'Msf::Simple::Auxiliary lifecycle wiring' do
  let(:events) { double('events', on_module_run: nil, on_module_complete: nil) }
  let(:framework) { double('framework', events: events, db: double('db', active: false)) }
  let(:execution) { double('execution', id: 11) }

  let(:mod_class) do
    Class.new do
      attr_accessor :error, :fail_reason, :fail_detail, :check_code, :last_vuln_attempt
      attr_writer :user_input, :user_output
      attr_reader :framework, :datastore

      def initialize(framework, type: 'auxiliary')
        @framework = framework
        @type = type
        @datastore = { 'RHOSTS' => '192.0.2.10' }
        @fail_reason = Msf::Module::Failure::None
      end

      def type; @type; end
      def fullname; 'auxiliary/scanner/test'; end
      def refname; 'scanner/test'; end
      def init_ui(_i, _o); end
      def setup; end
      def cleanup; end
      def report_failure; end
      def run; :ok; end
      def check; Msf::Exploit::CheckCode::Vulnerable; end
      def print_error(_msg); end
      def print_status(_msg); end
    end
  end

  let(:mod) { mod_class.new(framework) }
  let(:run_uuid) { 'uuid-test' }
  let(:listener) { Msf::Simple::NoopJobListener.instance }

  describe 'run path' do
    let(:ctx) do
      [mod, run_uuid, listener,
       { originating_interface: 'console', kind: Msf::Reporting::Execution::KIND_RUN }]
    end

    it 'starts an execution, exposes it as current, and finalizes success' do
      expect(Msf::Reporting::Execution).to receive(:start!).with(
        hash_including(
          framework: framework,
          mod: mod,
          originating_interface: 'console',
          kind: 'run'
        )
      ).and_return(execution)

      expect(mod).to receive(:run).and_wrap_original do |original|
        expect(Msf::Reporting::CurrentExecution.current).to be(execution)
        original.call
      end

      expect(Msf::Reporting::Execution).to receive(:finalize!).with(
        execution,
        terminal_status: 'success',
        failure_reason: nil,
        failure_message: nil,
        check_code: nil,
        check_message: nil
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
      expect(Msf::Reporting::CurrentExecution.current).to be_nil
    end

    it 'finalizes as expected_failure when mod.fail_reason is set' do
      mod.fail_reason = Msf::Module::Failure::NoTarget
      mod.fail_detail = 'no target'
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      expect(Msf::Reporting::Execution).to receive(:finalize!).with(
        execution,
        terminal_status: 'expected_failure',
        failure_reason: Msf::Module::Failure::NoTarget,
        failure_message: 'no target',
        check_code: nil,
        check_message: nil
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
    end

    it 'finalizes as unhandled_exception when run! raises an unexpected error' do
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      allow(mod).to receive(:run).and_raise(RuntimeError, 'kaboom')

      expect(Msf::Reporting::Execution).to receive(:finalize!).with(
        execution,
        terminal_status: 'unhandled_exception',
        failure_reason: Msf::Module::Failure::Unknown,
        failure_message: 'kaboom',
        check_code: nil,
        check_message: nil
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
    end
  end

  describe 'check path' do
    let(:ctx) do
      [mod, run_uuid, listener,
       { originating_interface: 'console', kind: Msf::Reporting::Execution::KIND_CHECK }]
    end

    it 'creates an execution with kind=check and maps Vulnerable -> success' do
      expect(Msf::Reporting::Execution).to receive(:start!).with(
        hash_including(kind: 'check')
      ).and_return(execution)
      expect(Msf::Reporting::Execution).to receive(:finalize!).with(
        execution,
        terminal_status: 'success',
        failure_reason: nil,
        failure_message: nil,
        check_code: Msf::Exploit::CheckCode::Vulnerable,
        check_message: Msf::Exploit::CheckCode::Vulnerable.message
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx) { |m| m.check }
    end

    it 'maps Safe -> neutral' do
      allow(mod).to receive(:check).and_return(Msf::Exploit::CheckCode::Safe)
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      expect(Msf::Reporting::Execution).to receive(:finalize!).with(
        execution,
        terminal_status: 'neutral',
        failure_reason: nil,
        failure_message: nil,
        check_code: Msf::Exploit::CheckCode::Safe,
        check_message: Msf::Exploit::CheckCode::Safe.message
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx) { |m| m.check }
    end

    it 'maps a raised exception -> unhandled_exception' do
      allow(mod).to receive(:check).and_raise(RuntimeError, 'check broke')
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      expect(Msf::Reporting::Execution).to receive(:finalize!).with(
        execution,
        terminal_status: 'unhandled_exception',
        failure_reason: nil,
        failure_message: 'check broke',
        check_code: nil,
        check_message: nil
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx) { |m| m.check }
    end

    it 'maps a fail_with inside check to expected_failure with typed reason and detail' do
      allow(mod).to receive(:check) do
        mod.fail_reason = Msf::Module::Failure::NoTarget
        mod.fail_detail = 'no target from check'
        raise Msf::Auxiliary::Failed, 'no target from check'
      end
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      expect(Msf::Reporting::Execution).to receive(:finalize!).with(
        execution,
        terminal_status: 'expected_failure',
        failure_reason: Msf::Module::Failure::NoTarget,
        failure_message: 'no target from check',
        check_code: nil,
        check_message: nil
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx) { |m| m.check }
    end
  end

  describe 'cleanup on the happy path' do
    let(:ctx) do
      [mod, run_uuid, listener,
       { originating_interface: 'console', kind: Msf::Reporting::Execution::KIND_RUN }]
    end

    it 'invokes mod.cleanup exactly once on the happy path' do
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      allow(Msf::Reporting::Execution).to receive(:finalize!)
      expect(mod).to receive(:cleanup).once

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
    end

    it 'invokes mod.cleanup while CurrentExecution is still bound to the execution' do
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      allow(Msf::Reporting::Execution).to receive(:finalize!)

      observed = nil
      allow(mod).to receive(:cleanup) do
        observed = Msf::Reporting::CurrentExecution.current
      end

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
      expect(observed).to be(execution)
    end

    it 'wraps mod.cleanup with with_phase_cleanup so raised exceptions record phase=cleanup' do
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      allow(Msf::Reporting::Execution).to receive(:finalize!)
      allow(mod).to receive(:cleanup).and_raise(RuntimeError, 'cleanup boom')

      expect(::Mdm::ModuleExecutionError).to receive(:create!).with(
        hash_including(
          module_execution: execution,
          lifecycle_phase: 'cleanup',
          exception_class: 'RuntimeError'
        )
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
    end

    it 'does not invoke mod.cleanup twice when a rescue branch also runs cleanup' do
      allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
      allow(Msf::Reporting::Execution).to receive(:finalize!)
      allow(mod).to receive(:run).and_raise(Msf::Auxiliary::Complete)
      expect(mod).to receive(:cleanup).once

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx, &:run)
    end

    it 'notify_job_complete does NOT re-invoke mod.cleanup' do
      allow(mod.framework.events).to receive(:on_module_complete)
      expect(mod).not_to receive(:cleanup)

      Msf::Simple::Auxiliary.send(:notify_job_complete, [mod])
    end
  end
end
