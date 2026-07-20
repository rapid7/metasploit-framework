# frozen_string_literal: true

require 'msf/core/mcp'
require 'stringio'
require 'json'

RSpec.describe Msf::MCP::Logging::Sinks::JsonStream do
  let(:stream) { StringIO.new }
  let(:sink) { described_class.new(stream) }
  let(:log_source) { Msf::MCP::LOG_SOURCE }

  # Helper: parse the last JSON line written to the stream
  def last_entry
    stream.rewind
    lines = stream.read.strip.split("\n")
    JSON.parse(lines.last)
  end

  describe '#initialize' do
    it 'accepts any IO-like stream' do
      expect { described_class.new(StringIO.new) }.not_to raise_error
    end

    it 'includes Rex::Logging::LogSink' do
      expect(described_class.ancestors).to include(Rex::Logging::LogSink)
    end
  end

  describe '#log' do
    it 'writes JSON to the stream' do
      sink.log(:info, 'mcp', 0, 'test')
      expect(last_entry).to be_a(Hash)
    end

    it 'flushes after each write' do
      expect(stream).to receive(:flush).once
      sink.log(:info, 'mcp', 0, 'test')
    end

    it 'appends a newline after each entry' do
      sink.log(:info, 'mcp', 0, 'test')
      stream.rewind
      expect(stream.read).to end_with("\n")
    end

    it 'includes a timestamp' do
      sink.log(:info, 'mcp', 0, 'test')
      expect(last_entry['timestamp']).not_to be_nil
    end

    it 'uppercases the severity' do
      sink.log(:error, 'mcp', 0, 'test')
      expect(last_entry['severity']).to eq('ERROR')
    end

    it 'converts level to string' do
      sink.log(:info, 'mcp', 2, 'test')
      expect(last_entry['level']).to eq('2')
    end

    it 'converts source to string' do
      sink.log(:info, :mcp, 0, 'test')
      expect(last_entry['source']).to eq('mcp')
    end

    context 'with a String message' do
      it 'uses the string as message' do
        sink.log(:info, 'mcp', 0, 'plain text')
        expect(last_entry['message']).to eq('plain text')
      end

      it 'does not include context or exception keys' do
        sink.log(:info, 'mcp', 0, 'plain text')
        expect(last_entry).not_to have_key('context')
        expect(last_entry).not_to have_key('exception')
      end
    end

    context 'with a Hash message' do
      it 'extracts :message from the hash' do
        sink.log(:info, 'mcp', 0, { message: 'structured' })
        expect(last_entry['message']).to eq('structured')
      end

      it 'falls back to hash.to_s when :message is nil' do
        sink.log(:info, 'mcp', 0, { context: { a: 1 } })
        # message is the Hash#to_s representation since :message key is absent
        expect(last_entry['message']).to include('context')
      end

      it 'does not overwrite message when :message is empty string' do
        sink.log(:info, 'mcp', 0, { message: '', context: { a: 1 } })
        # Empty :message is skipped, so message stays as hash.to_s
        expect(last_entry['message']).to include('context')
      end

      it 'includes :context when present and non-empty' do
        sink.log(:info, 'mcp', 0, { message: 'test', context: { tool: 'search' } })
        expect(last_entry['context']).to eq({ 'tool' => 'search' })
      end

      it 'omits :context when nil' do
        sink.log(:info, 'mcp', 0, { message: 'test', context: nil })
        expect(last_entry).not_to have_key('context')
      end

      it 'omits :context when empty hash' do
        sink.log(:info, 'mcp', 0, { message: 'test', context: {} })
        expect(last_entry).not_to have_key('context')
      end
    end

    context 'with an Exception in :exception' do
      let(:error) do
        StandardError.new('boom').tap do |e|
          e.set_backtrace(%w[line1 line2 line3 line4 line5 line6])
        end
      end

      it 'formats the exception as a structured hash' do
        sink.log(:error, 'mcp', 0, { message: 'fail', exception: error })
        ex = last_entry['exception']

        expect(ex['class']).to eq('StandardError')
        expect(ex['message']).to eq('boom')
      end

      it 'includes backtrace at DEBUG log level' do
        # Register at LEV_3 (DEBUG) to enable backtrace
        deregister_log_source(log_source) if log_source_registered?(log_source)
        register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new('/dev/null'), Rex::Logging::LEV_3)

        sink.log(:error, 'mcp', 0, { message: 'fail', exception: error })
        ex = last_entry['exception']

        expect(ex['backtrace']).to be_an(Array)
        expect(ex['backtrace'].length).to eq(5) # first(5)
        expect(ex['backtrace']).not_to include('line6')

        deregister_log_source(log_source)
      end

      it 'omits backtrace below DEBUG log level' do
        # Register at LEV_0 — below BACKTRACE_LOG_LEVEL (3)
        deregister_log_source(log_source) if log_source_registered?(log_source)
        register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new('/dev/null'), Rex::Logging::LEV_0)

        sink.log(:error, 'mcp', 0, { message: 'fail', exception: error })
        ex = last_entry['exception']

        expect(ex).not_to have_key('backtrace')

        deregister_log_source(log_source)
      end

      it 'handles exception with nil backtrace' do
        no_bt = RuntimeError.new('no trace')
        # backtrace is nil by default when not raised

        sink.log(:error, 'mcp', 0, { message: 'fail', exception: no_bt })
        ex = last_entry['exception']

        expect(ex['class']).to eq('RuntimeError')
        expect(ex['message']).to eq('no trace')
      end

      it 'passes non-Exception :exception values through' do
        sink.log(:error, 'mcp', 0, { message: 'fail', exception: 'string error' })
        expect(last_entry['exception']).to eq('string error')
      end
    end

    context 'context summarization at non-DEBUG level' do
      before do
        # Register at LEV_0 so debug_log_level? returns false
        deregister_log_source(log_source) if log_source_registered?(log_source)
        register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new('/dev/null'), Rex::Logging::LEV_0)
      end

      after do
        deregister_log_source(log_source) if log_source_registered?(log_source)
      end

      it 'truncates heavy keys (:result, :body, :error)' do
        long_value = 'x' * 2000
        sink.log(:info, 'mcp', 0, { message: 'test', context: { result: long_value } })
        ctx = last_entry['context']

        expect(ctx['result']).to include('truncated')
        expect(ctx['result'].length).to be < 2000
      end

      it 'passes through non-heavy scalar keys unchanged' do
        sink.log(:info, 'mcp', 0, { message: 'test', context: { method: 'tools/call', elapsed_ms: 42 } })
        ctx = last_entry['context']

        expect(ctx['method']).to eq('tools/call')
        expect(ctx['elapsed_ms']).to eq(42)
      end

      it 'truncates heavy keys inside :response sub-hash' do
        long_result = 'y' * 2000
        context = { response: { status: 200, result: long_result } }
        sink.log(:info, 'mcp', 0, { message: 'test', context: context })
        resp = last_entry['context']['response']

        expect(resp['status']).to eq(200)
        expect(resp['result']).to include('truncated')
      end

      it 'does not truncate short values' do
        sink.log(:info, 'mcp', 0, { message: 'test', context: { result: 'short' } })
        ctx = last_entry['context']

        expect(ctx['result']).to eq('short')
      end
    end

    context 'context at DEBUG level' do
      before do
        deregister_log_source(log_source) if log_source_registered?(log_source)
        register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new('/dev/null'), Rex::Logging::LEV_3)
      end

      after do
        deregister_log_source(log_source) if log_source_registered?(log_source)
      end

      it 'passes context through without summarization' do
        long_value = 'x' * 2000
        sink.log(:info, 'mcp', 0, { message: 'test', context: { result: long_value } })
        ctx = last_entry['context']

        expect(ctx['result']).to eq(long_value)
        expect(ctx['result']).not_to include('truncated')
      end
    end
  end

  describe '#cleanup' do
    it 'closes the stream' do
      sink.cleanup
      expect(stream).to be_closed
    end
  end
end
