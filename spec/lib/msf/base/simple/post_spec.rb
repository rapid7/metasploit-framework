# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Simple::Post do
  let(:cleanup_calls) { [] }

  let(:events_double) do
    double('events').tap do |e|
      allow(e).to receive(:on_module_run)
      allow(e).to receive(:on_module_complete)
      allow(e).to receive(:on_session_module_run)
    end
  end

  let(:sessions_double) do
    double('sessions').tap do |s|
      allow(s).to receive(:get).and_return(nil)
    end
  end

  let(:framework_double) do
    double('framework',
           events: events_double,
           sessions: sessions_double)
  end

  let(:mod) do
    calls_ref = cleanup_calls
    fw_double = framework_double

    instance = Object.new
    instance.define_singleton_method(:framework) { fw_double }
    instance.define_singleton_method(:setup) {}
    instance.define_singleton_method(:print_error) { |_msg| }
    instance.define_singleton_method(:print_status) { |_msg| }
    instance.define_singleton_method(:elog) { |_msg, **_kw| }
    instance.define_singleton_method(:datastore) { { 'SESSION' => '1' } }
    instance.define_singleton_method(:error=) { |_v| }
    instance.define_singleton_method(:run) { nil }
    instance.define_singleton_method(:cleanup) { calls_ref << 1 }
    instance
  end

  def run_proc(mod)
    described_class.send(:job_run_proc, [mod])
  end

  def cleanup_proc(mod)
    described_class.send(:job_cleanup_proc, [mod])
  end

  describe '.job_run_proc' do
    context 'when the session is not found' do
      it 'does not call cleanup' do
        run_proc(mod)
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module raises Post::Failed' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise Msf::Post::Failed, 'intentional failure' }
      end

      it 'does not call cleanup' do
        run_proc(mod)
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module raises Post::Complete' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise Msf::Post::Complete }
      end

      it 'does not call cleanup' do
        run_proc(mod)
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module raises Timeout::Error' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise ::Timeout::Error }
      end

      it 'does not call cleanup' do
        run_proc(mod)
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module raises a generic Exception' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise 'unexpected error' }
      end

      it 'does not call cleanup' do
        run_proc(mod)
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module completes normally' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { nil }
      end

      it 'does not call cleanup' do
        run_proc(mod)
        expect(cleanup_calls.length).to eq(0)
      end
    end
  end

  describe '.job_cleanup_proc' do
    it 'calls cleanup exactly once' do
      cleanup_proc(mod)
      expect(cleanup_calls.length).to eq(1)
    end
  end

  describe 'cleanup is called exactly once across job_run_proc + job_cleanup_proc' do
    def run_then_cleanup(mod)
      run_proc(mod)
      cleanup_proc(mod)
    end

    context 'when the session is not found' do
      it 'calls cleanup exactly once total' do
        run_then_cleanup(mod)
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module raises Post::Failed' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise Msf::Post::Failed, 'intentional failure' }
      end

      it 'calls cleanup exactly once total' do
        run_then_cleanup(mod)
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module raises Post::Complete' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise Msf::Post::Complete }
      end

      it 'calls cleanup exactly once total' do
        run_then_cleanup(mod)
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module raises Timeout::Error' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise ::Timeout::Error }
      end

      it 'calls cleanup exactly once total' do
        run_then_cleanup(mod)
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module raises a generic Exception' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { raise 'unexpected error' }
      end

      it 'calls cleanup exactly once total' do
        run_then_cleanup(mod)
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module completes normally' do
      let(:session_double) { double('session') }

      before do
        allow(sessions_double).to receive(:get).and_return(session_double)
        allow(mod).to receive(:run) { nil }
      end

      it 'calls cleanup exactly once total' do
        run_then_cleanup(mod)
        expect(cleanup_calls.length).to eq(1)
      end
    end
  end
end
