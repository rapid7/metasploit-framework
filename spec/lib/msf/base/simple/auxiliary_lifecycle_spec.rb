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
        failure_message: nil
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
        failure_message: 'no target'
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
        failure_message: 'kaboom'
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
        failure_message: nil
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
        failure_message: nil
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
        failure_message: 'check broke'
      )

      Msf::Simple::Auxiliary.send(:job_run_proc, ctx) { |m| m.check }
    end
  end
end
