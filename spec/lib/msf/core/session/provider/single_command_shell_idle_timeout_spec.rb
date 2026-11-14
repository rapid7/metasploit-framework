# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Session::Provider::SingleCommandShell do
  let(:token) { 'TOKENTOKENTOKEN' }

  let(:shell_class) do
    Class.new do
      include Msf::Session::Provider::SingleCommandShell

      def initialize(&reader)
        @reader = reader
      end

      def shell_read(*_args)
        sleep(0.1)
        @reader.call
      end

      def shell_write(_data); end

      def command_termination
        "\n"
      end
    end
  end

  def scripted(chunks)
    queue = chunks.dup
    -> { queue.shift }
  end

  def timed
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = yield
    [result, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started]
  end

  describe '#shell_read_until_token' do
    let(:steady_output) { Array.new(15, 'abc') + ["#{token}\r\n"] }

    it 'uses an absolute deadline by default' do
      shell = shell_class.new(&scripted(steady_output))
      result, elapsed = timed { shell.shell_read_until_token(token, 0, 1) }

      expect(result).to be_nil
      expect(elapsed).to be < 2
    end

    it 'keeps reading while data is still arriving inside with_idle_read_timeout' do
      shell = shell_class.new(&scripted(steady_output))
      result = shell.with_idle_read_timeout(10) { shell.shell_read_until_token(token, 0, 1) }

      expect(result).to eq('abc' * 15)
    end

    it 'gives up once nothing has arrived for the idle timeout' do
      shell = shell_class.new(&scripted(['abc']))
      result, elapsed = timed do
        shell.with_idle_read_timeout(10) { shell.shell_read_until_token(token, 0, 1) }
      end

      expect(result).to be_nil
      expect(elapsed).to be_between(0.9, 3)
    end

    it 'enforces the absolute ceiling when output never stops' do
      shell = shell_class.new { 'x' }
      result, elapsed = timed do
        shell.with_idle_read_timeout(2) { shell.shell_read_until_token(token, 0, 1) }
      end

      expect(result).to be_nil
      expect(elapsed).to be_between(1.5, 3.5)
    end
  end

  describe '#with_idle_read_timeout' do
    it 'returns the value of the block' do
      shell = shell_class.new { nil }

      expect(shell.with_idle_read_timeout(5) { :done }).to eq(:done)
    end

    it 'restores the absolute deadline afterwards, even when the block raises' do
      shell = shell_class.new { 'x' }

      expect { shell.with_idle_read_timeout(5) { raise 'boom' } }.to raise_error('boom')

      result, elapsed = timed { shell.shell_read_until_token(token, 0, 1) }
      expect(result).to be_nil
      expect(elapsed).to be < 2
    end
  end
end
