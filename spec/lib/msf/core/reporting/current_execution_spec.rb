# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Reporting::CurrentExecution do
  after { described_class.clear }

  describe '.current' do
    it 'is nil when no execution has been set' do
      expect(described_class.current).to be_nil
    end
  end

  describe '.id' do
    it 'returns nil when no execution has been set' do
      expect(described_class.id).to be_nil
    end

    it 'returns the id of the current execution' do
      execution = double('execution', id: 42)
      described_class.with(execution) do
        expect(described_class.id).to eq(42)
      end
    end

    it 'returns nil when the current execution does not respond to #id' do
      described_class.with(Object.new) do
        expect(described_class.id).to be_nil
      end
    end
  end

  describe '.with' do
    it 'raises LocalJumpError when called without a block' do
      expect { described_class.with(double('execution')) }.to raise_error(LocalJumpError)
    end

    it 'sets the current execution for the duration of the block' do
      execution = double('execution')
      described_class.with(execution) do
        expect(described_class.current).to be(execution)
      end
      expect(described_class.current).to be_nil
    end

    it 'returns the block value' do
      expect(described_class.with(double('execution')) { :ok }).to eq(:ok)
    end

    it 'restores the previous value when nested' do
      outer = double('outer')
      inner = double('inner')
      described_class.with(outer) do
        expect(described_class.current).to be(outer)
        described_class.with(inner) do
          expect(described_class.current).to be(inner)
        end
        expect(described_class.current).to be(outer)
      end
    end

    it 'restores the previous value when the block raises' do
      execution = double('execution')
      expect do
        described_class.with(execution) { raise 'boom' }
      end.to raise_error('boom')
      expect(described_class.current).to be_nil
    end

    it 'accepts a nil execution and clears the slot inside the block' do
      outer = double('outer')
      described_class.with(outer) do
        described_class.with(nil) do
          expect(described_class.current).to be_nil
        end
        expect(described_class.current).to be(outer)
      end
    end
  end

  describe '.clear' do
    it 'clears the current execution' do
      execution = double('execution')
      Thread.current[:msf_reporting_current_execution] = execution
      described_class.clear
      expect(described_class.current).to be_nil
    end
  end

  describe 'thread isolation' do
    it 'keeps the current execution per-thread' do
      execution = double('execution')
      other_thread_value = nil
      described_class.with(execution) do
        Thread.new { other_thread_value = described_class.current }.join
      end
      expect(other_thread_value).to be_nil
    end
  end
end
