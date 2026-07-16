# frozen_string_literal: true

require 'spec_helper'

# Thread-local phase override wired into +Execution.phase_for+.
# Mirrors the shape of +Msf::Reporting::CurrentExecution+.
RSpec.describe Msf::Reporting::CurrentPhase do
  after { described_class.clear }

  describe '.current' do
    it 'defaults to nil' do
      expect(described_class.current).to be_nil
    end
  end

  describe '.with' do
    it 'sets the current phase for the duration of the block' do
      inside = nil
      described_class.with('setup') do
        inside = described_class.current
      end

      expect(inside).to eq('setup')
      expect(described_class.current).to be_nil
    end

    it 'restores the previous phase on normal exit, allowing nesting' do
      described_class.with('setup') do
        described_class.with('cleanup') do
          expect(described_class.current).to eq('cleanup')
        end
        expect(described_class.current).to eq('setup')
      end
      expect(described_class.current).to be_nil
    end

    it 'restores the previous phase when the block raises' do
      expect do
        described_class.with('setup') do
          raise 'boom'
        end
      end.to raise_error(RuntimeError, 'boom')

      expect(described_class.current).to be_nil
    end

    it 'coerces a Symbol to a String' do
      described_class.with(:cleanup) do
        expect(described_class.current).to eq('cleanup')
      end
    end

    it 'accepts nil to explicitly clear inside the block' do
      described_class.with('setup') do
        described_class.with(nil) do
          expect(described_class.current).to be_nil
        end
        expect(described_class.current).to eq('setup')
      end
    end

    it 'raises when called without a block' do
      expect { described_class.with('setup') }.to raise_error(LocalJumpError)
    end
  end

  describe 'thread isolation' do
    it 'does not leak the phase across threads' do
      seen_in_thread = nil

      described_class.with('setup') do
        t = Thread.new { seen_in_thread = described_class.current }
        t.join
      end

      expect(seen_in_thread).to be_nil
    end
  end
end
