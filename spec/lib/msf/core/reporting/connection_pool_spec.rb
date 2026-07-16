# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Reporting::ConnectionPool do
  describe '.with_connection' do
    let(:pool) do
      pool_double = double('connection_pool')
      allow(pool_double).to receive(:with_connection) { |&block| block.call }
      pool_double
    end

    before do
      allow(::ApplicationRecord).to receive(:connection_pool).and_return(pool)
    end

    it 'raises when called without a block' do
      expect { described_class.with_connection }.to raise_error(LocalJumpError)
    end

    it 'yields and returns the block value' do
      expect(described_class.with_connection { 42 }).to eq(42)
    end

    it 'checks out an AR connection via ApplicationRecord.connection_pool' do
      expect(pool).to receive(:with_connection) { |&block| block.call }
      described_class.with_connection { :ok }
    end

    it 'propagates exceptions raised inside the block' do
      expect do
        described_class.with_connection { raise ArgumentError, 'boom' }
      end.to raise_error(ArgumentError, 'boom')
    end

    context 'release semantics (delegated to ActiveRecord)' do
      let(:released) { [] }

      before do
        allow(pool).to receive(:with_connection) do |&block|
          block.call
        ensure
          released << :released
        end
      end

      it 'releases the connection on normal block exit' do
        described_class.with_connection { :ok }
        expect(released).to eq([:released])
      end

      it 'releases the connection when the block raises' do
        expect do
          described_class.with_connection { raise 'x' }
        end.to raise_error('x')

        expect(released).to eq([:released])
      end

      it 'releases the connection on early return inside the block' do
        helper = Class.new do
          def call
            Msf::Reporting::ConnectionPool.with_connection do
              return :early
            end
            :did_not_return
          end
        end

        expect(helper.new.call).to eq(:early)
        expect(released).to eq([:released])
      end

      it 'releases the connection when Thread#raise interrupts the block' do
        ready = Queue.new

        thread = Thread.new do
          Thread.current.report_on_exception = false
          described_class.with_connection do
            ready << :inside
            sleep
          end
        end

        ready.pop
        thread.raise(StandardError, 'interrupted')

        expect { thread.value }.to raise_error(StandardError, 'interrupted')
        expect(released).to eq([:released])
      end
    end

    context 'when ApplicationRecord is not defined' do
      before { hide_const('ApplicationRecord') }

      it 'yields the block directly without any AR interaction' do
        expect(described_class.with_connection { 7 }).to eq(7)
      end
    end
  end
end
