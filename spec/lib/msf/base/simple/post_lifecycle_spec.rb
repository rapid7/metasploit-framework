# frozen_string_literal: true

require 'spec_helper'

# Verifies +Msf::Simple::Post.job_run_proc+ wires the execution
# lifecycle around post-module runs.
RSpec.describe 'Msf::Simple::Post lifecycle wiring' do
  let(:sessions) { double('sessions', get: double('session')) }
  let(:events) do
    double('events',
           on_module_run: nil,
           on_module_complete: nil,
           on_session_module_run: nil)
  end
  let(:framework) do
    double('framework',
           events: events,
           sessions: sessions,
           db: double('db', active: false))
  end
  let(:execution) { double('execution', id: 7) }

  let(:mod_class) do
    Class.new do
      attr_accessor :error
      attr_reader :framework, :datastore

      def initialize(framework)
        @framework = framework
        @datastore = { 'SESSION' => 1 }
      end

      def type; 'post'; end
      def fullname; 'post/multi/general/execute'; end
      def refname; 'multi/general/execute'; end
      def setup; end
      def cleanup; end
      def run; :ok; end
      def print_error(_msg); end
    end
  end

  let(:mod) { mod_class.new(framework) }
  let(:ctx) { [mod, { originating_ui: 'console' }] }

  it 'starts an execution, exposes it as current, and finalizes success' do
    expect(Msf::Reporting::Execution).to receive(:start!).with(
      hash_including(framework: framework, mod: mod, originating_ui: 'console', kind: 'run')
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

    Msf::Simple::Post.send(:job_run_proc, ctx)
  end

  it 'finalizes as unhandled_exception when run raises' do
    allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
    allow(mod).to receive(:run).and_raise(RuntimeError, 'boom')

    expect(Msf::Reporting::Execution).to receive(:finalize!).with(
      execution,
      terminal_status: 'unhandled_exception',
      failure_reason: nil,
      failure_message: 'boom'
    )

    Msf::Simple::Post.send(:job_run_proc, ctx)
  end
end
