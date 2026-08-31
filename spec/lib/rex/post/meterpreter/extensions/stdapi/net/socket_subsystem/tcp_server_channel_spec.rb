# frozen_string_literal: true

require 'spec_helper'
require 'thread'
require 'rex/socket'

# Behavioral tests for the TcpServerChannel accept/accept_nonblock logic.
# Uses a harness replicating the Queue-based implementation to avoid needing
# the full meterpreter TLV dependency chain.
RSpec.describe 'TcpServerChannel accept logic' do
  let(:queue) { Queue.new }
  let(:mock_lsock) do
    obj = double('lsock')
    allow(obj).to receive(:kind_of?).with(Rex::Socket::Tcp).and_return(true)
    obj
  end
  let(:mock_channel) { double('client_channel', lsock: mock_lsock) }

  # Harness replicating the accept/_accept logic
  let(:acceptor) do
    q = queue
    obj = Object.new

    obj.define_singleton_method(:accept) do |opts = {}|
      timeout = opts['Timeout']
      if timeout.nil? || timeout <= 0
        timeout = nil
      end
      obj.send(:_accept, timeout: timeout)
    end

    obj.define_singleton_method(:accept_nonblock) do
      obj.send(:_accept, nonblock: true)
    end

    obj.define_singleton_method(:_accept) do |nonblock: false, timeout: nil|
      result = nil
      begin
        if nonblock
          channel = q.deq(true)
        elsif timeout
          channel = q.deq(timeout: timeout)
        else
          channel = q.deq
        end

        if channel
          result = channel.lsock
        end

        if result != nil && !result.kind_of?(Rex::Socket::Tcp)
          result.extend(Rex::Socket::Tcp)
        end
      rescue ThreadError
      end
      result
    end

    obj
  end

  describe '#accept' do
    context 'with a timeout and empty queue' do
      it 'returns nil without hanging' do
        start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = acceptor.accept('Timeout' => 0.3)
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start

        expect(result).to be_nil
        expect(elapsed).to be < 1.0
      end
    end

    context 'with a timeout and connection already enqueued' do
      it 'returns the lsock' do
        queue.enq(mock_channel)
        result = acceptor.accept('Timeout' => 2)
        expect(result).to eq(mock_lsock)
      end
    end

    context 'with nil/zero timeout blocks until available' do
      it 'blocks then returns lsock when connection arrives' do
        Thread.new do
          sleep 0.1
          queue.enq(mock_channel)
        end

        result = acceptor.accept('Timeout' => 0)
        expect(result).to eq(mock_lsock)
      end
    end
  end

  describe '#accept_nonblock' do
    context 'when queue is empty' do
      it 'returns nil immediately' do
        start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = acceptor.accept_nonblock
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start

        expect(result).to be_nil
        expect(elapsed).to be < 0.1
      end
    end

    context 'when connection is available' do
      it 'returns the lsock' do
        queue.enq(mock_channel)
        result = acceptor.accept_nonblock
        expect(result).to eq(mock_lsock)
      end
    end
  end
end
