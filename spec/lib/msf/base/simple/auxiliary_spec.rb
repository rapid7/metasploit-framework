# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Simple::Auxiliary do
  let(:cleanup_calls) { [] }

  let(:events_double) do
    double('events').tap do |e|
      allow(e).to receive(:on_module_run)
      allow(e).to receive(:on_module_complete)
    end
  end

  let(:framework_double) do
    double('framework', events: events_double)
  end

  let(:job_listener) { Msf::Simple::NoopJobListener.instance }

  let(:mod) do
    calls_ref = cleanup_calls
    fw_double = framework_double

    instance = Object.new
    instance.define_singleton_method(:framework) { fw_double }
    instance.define_singleton_method(:setup) {}
    instance.define_singleton_method(:print_error) { |_msg| }
    instance.define_singleton_method(:print_status) { |_msg| }
    instance.define_singleton_method(:elog) { |_msg, **_kw| }
    instance.define_singleton_method(:fail_reason) { Msf::Module::Failure::None }
    instance.define_singleton_method(:fail_reason=) { |_v| }
    instance.define_singleton_method(:fail_detail) { nil }
    instance.define_singleton_method(:fail_detail=) { |_v| }
    instance.define_singleton_method(:error=) { |_v| }
    instance.define_singleton_method(:report_failure) {}
    instance.define_singleton_method(:cleanup) { calls_ref << 1 }
    instance
  end

  let(:run_uuid) { 'test-run-uuid-1234' }
  let(:ctx) { [mod, run_uuid, job_listener] }

  def run_proc(ctx, &block)
    block ||= proc { |_m| }
    described_class.send(:job_run_proc, ctx, &block)
  end

  def cleanup_proc(ctx)
    described_class.send(:job_cleanup_proc, ctx)
  end

  describe '.job_run_proc' do
    context 'when the module raises Auxiliary::Failed' do
      it 'does not call cleanup' do
        run_proc(ctx) { raise Msf::Auxiliary::Failed, 'intentional failure' }
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module raises Auxiliary::Complete' do
      it 'does not call cleanup' do
        run_proc(ctx) { raise Msf::Auxiliary::Complete }
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module raises Timeout::Error' do
      it 'does not call cleanup' do
        run_proc(ctx) { raise ::Timeout::Error }
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module raises a generic Exception' do
      it 'does not call cleanup' do
        run_proc(ctx) { raise 'unexpected error' }
        expect(cleanup_calls.length).to eq(0)
      end
    end

    context 'when the module completes normally' do
      it 'does not call cleanup' do
        run_proc(ctx) { nil }
        expect(cleanup_calls.length).to eq(0)
      end
    end
  end

  describe '.job_cleanup_proc' do
    it 'calls cleanup exactly once' do
      cleanup_proc(ctx)
      expect(cleanup_calls.length).to eq(1)
    end
  end

  describe 'cleanup is called exactly once across job_run_proc + job_cleanup_proc' do
    def run_then_cleanup(ctx, &block)
      block ||= proc { |_m| }
      run_proc(ctx, &block)
      cleanup_proc(ctx)
    end

    context 'when the module raises Auxiliary::Failed' do
      it 'calls cleanup exactly once total' do
        run_then_cleanup(ctx) { raise Msf::Auxiliary::Failed, 'intentional failure' }
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module raises Auxiliary::Complete' do
      it 'calls cleanup exactly once total' do
        run_then_cleanup(ctx) { raise Msf::Auxiliary::Complete }
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module raises Timeout::Error' do
      it 'calls cleanup exactly once total' do
        run_then_cleanup(ctx) { raise ::Timeout::Error }
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module raises a generic Exception' do
      it 'calls cleanup exactly once total' do
        run_then_cleanup(ctx) { raise 'unexpected error' }
        expect(cleanup_calls.length).to eq(1)
      end
    end

    context 'when the module completes normally' do
      it 'calls cleanup exactly once total' do
        run_then_cleanup(ctx) { nil }
        expect(cleanup_calls.length).to eq(1)
      end
    end
  end
end
