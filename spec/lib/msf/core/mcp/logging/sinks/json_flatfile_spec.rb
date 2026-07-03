# frozen_string_literal: true

require 'msf/core/mcp'
require 'tempfile'
require 'json'

RSpec.describe Msf::MCP::Logging::Sinks::JsonFlatfile do
  let(:log_path) { Tempfile.new(['json_flatfile_test', '.log']).tap(&:close).path }
  let(:sink) { described_class.new(log_path) }

  after do
    sink.cleanup rescue nil
    File.delete(log_path) if File.exist?(log_path)
  end

  describe '#initialize' do
    it 'creates the log file' do
      described_class.new(log_path)
      expect(File.exist?(log_path)).to be true
    end

    it 'opens the file in append mode' do
      # Write some content first
      File.write(log_path, "existing\n")
      new_sink = described_class.new(log_path)
      new_sink.log(:info, 'mcp', 0, 'appended')
      new_sink.cleanup

      content = File.read(log_path)
      expect(content).to start_with("existing\n")
      expect(content).to include('appended')
    end

    it 'inherits from JsonStream' do
      expect(described_class.superclass).to eq(Msf::MCP::Logging::Sinks::JsonStream)
    end
  end

  describe '#log' do
    it 'writes a JSON line to the file' do
      sink.log(:info, 'mcp', 0, 'test message')
      content = File.read(log_path)
      expect(content).not_to be_empty

      entry = JSON.parse(content.strip)
      expect(entry).to be_a(Hash)
    end

    it 'includes timestamp, severity, level, source, and message' do
      sink.log(:error, 'mcp', 2, 'something broke')
      entry = JSON.parse(File.read(log_path).strip)

      expect(entry['timestamp']).not_to be_nil
      expect(entry['severity']).to eq('ERROR')
      expect(entry['level']).to eq('2')
      expect(entry['source']).to eq('mcp')
      expect(entry['message']).to include('something broke')
    end

    it 'writes one JSON object per line' do
      sink.log(:info, 'mcp', 0, 'first')
      sink.log(:info, 'mcp', 0, 'second')

      lines = File.read(log_path).strip.split("\n")
      expect(lines.length).to eq(2)
      expect(JSON.parse(lines[0])['message']).to include('first')
      expect(JSON.parse(lines[1])['message']).to include('second')
    end

    context 'with a Hash message' do
      it 'extracts :message from the hash' do
        sink.log(:info, 'mcp', 0, { message: 'structured log' })
        entry = JSON.parse(File.read(log_path).strip)

        expect(entry['message']).to eq('structured log')
      end

      it 'includes :context when present' do
        sink.log(:info, 'mcp', 0, { message: 'with context', context: { tool: 'search' } })
        entry = JSON.parse(File.read(log_path).strip)

        expect(entry['context']).to be_a(Hash)
        expect(entry['context']['tool']).to eq('search')
      end

      it 'omits :context when empty' do
        sink.log(:info, 'mcp', 0, { message: 'no context', context: {} })
        entry = JSON.parse(File.read(log_path).strip)

        expect(entry).not_to have_key('context')
      end

      it 'formats Exception in :exception as structured hash' do
        error = StandardError.new('test error')
        error.set_backtrace(['line1', 'line2'])

        sink.log(:error, 'mcp', 0, { message: 'error occurred', exception: error })
        entry = JSON.parse(File.read(log_path).strip)

        expect(entry['exception']).to be_a(Hash)
        expect(entry['exception']['class']).to eq('StandardError')
        expect(entry['exception']['message']).to eq('test error')
      end

      it 'passes non-Exception :exception values through as-is' do
        sink.log(:error, 'mcp', 0, { message: 'error', exception: 'just a string' })
        entry = JSON.parse(File.read(log_path).strip)

        expect(entry['exception']).to eq('just a string')
      end
    end

    context 'with a String message' do
      it 'uses the string directly as message' do
        sink.log(:info, 'mcp', 0, 'plain string')
        entry = JSON.parse(File.read(log_path).strip)

        expect(entry['message']).to eq('plain string')
        expect(entry).not_to have_key('context')
        expect(entry).not_to have_key('exception')
      end
    end
  end

  describe '#cleanup' do
    it 'closes the underlying file' do
      sink.log(:info, 'mcp', 0, 'before cleanup')
      sink.cleanup

      # Writing after cleanup should raise (file is closed)
      expect { sink.log(:info, 'mcp', 0, 'after cleanup') }.to raise_error(IOError)
    end
  end
end
