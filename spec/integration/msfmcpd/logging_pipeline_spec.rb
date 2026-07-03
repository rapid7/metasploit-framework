# frozen_string_literal: true

require 'msf/core/mcp'
require 'stringio'
require 'tempfile'
require 'json'

RSpec.describe 'Logging Pipeline Integration' do
  let(:output) { StringIO.new }
  let(:log_file) { Tempfile.new(['logging_integration', '.log']).tap(&:close).path }
  let(:log_src) { Msf::MCP::LOG_SOURCE }
  let(:lvl_info) { Msf::MCP::LOG_INFO }
  let(:lvl_warn) { Msf::MCP::LOG_WARN }
  let(:lvl_error) { Msf::MCP::LOG_ERROR }

  after do
    deregister_log_source(log_src) if log_source_registered?(log_src)
    File.delete(log_file) if File.exist?(log_file)
  end

  describe 'initialize_logger with sanitize enabled' do
    it 'produces JSON log entries with sensitive data redacted' do
      app = Msf::MCP::Application.new([], output: output)
      app.send(:parse_arguments)
      app.instance_variable_set(:@config, {
        logging: {
          enabled: true,
          level: 'INFO',
          log_file: log_file,
          sanitize: true
        }
      })
      app.send(:initialize_logger)

      ilog({ message: 'Connection established', context: { password: 's3cret', host: 'localhost' } }, log_src, lvl_info)

      content = File.read(log_file)
      expect(content).not_to be_empty

      entry = JSON.parse(content.strip.split("\n").last)

      expect(entry['timestamp']).not_to be_nil
      expect(entry['severity']).to eq('INFO')
      expect(entry['message']).to include('Connection established')

      expect(entry['context']['password']).to eq('[REDACTED]')
      expect(entry['context']['host']).to eq('localhost')

      expect(content).not_to include('s3cret')
    end
  end

  describe 'initialize_logger with sanitize disabled' do
    it 'produces JSON log entries without redaction' do
      app = Msf::MCP::Application.new([], output: output)
      app.send(:parse_arguments)
      app.instance_variable_set(:@config, {
        logging: {
          enabled: true,
          level: 'INFO',
          log_file: log_file,
          sanitize: false
        }
      })
      app.send(:initialize_logger)

      ilog({ message: 'Connection established', context: { password: 's3cret', host: 'localhost' } }, log_src, lvl_info)

      content = File.read(log_file)
      entry = JSON.parse(content.strip.split("\n").last)

      expect(entry['severity']).to eq('INFO')
      expect(entry['message']).to include('Connection established')

      expect(entry['context']['password']).to eq('s3cret')
      expect(entry['context']['host']).to eq('localhost')
    end
  end

  describe 'log level filtering' do
    it 'filters messages below the configured threshold' do
      app = Msf::MCP::Application.new([], output: output)
      app.send(:parse_arguments)
      app.instance_variable_set(:@config, {
        logging: {
          enabled: true,
          level: 'WARN',
          log_file: log_file,
          sanitize: false
        }
      })
      app.send(:initialize_logger)

      # INFO (LEV_2) should be filtered at WARN (LEV_1) threshold
      ilog({ message: 'This should be filtered' }, log_src, lvl_info)
      # WARN (LEV_1) should pass
      wlog({ message: 'This should appear' }, log_src, lvl_warn)
      # ERROR (LEV_0) should pass
      elog({ message: 'This error should appear' }, log_src, lvl_error)

      content = File.read(log_file)
      lines = content.strip.split("\n").reject(&:empty?)

      expect(lines.length).to eq(2)

      entries = lines.map { |l| JSON.parse(l) }
      expect(entries.map { |e| e['severity'] }).to contain_exactly('WARN', 'ERROR')
      expect(content).not_to include('This should be filtered')
    end
  end

  describe 'exception logging through the pipeline' do
    it 'formats exceptions as structured JSON with sanitized messages' do
      app = Msf::MCP::Application.new([], output: output)
      app.send(:parse_arguments)
      app.instance_variable_set(:@config, {
        logging: {
          enabled: true,
          level: 'ERROR',
          log_file: log_file,
          sanitize: true
        }
      })
      app.send(:initialize_logger)

      error = StandardError.new('Failed with password=hunter2')
      error.set_backtrace(['lib/msf/core/mcp/server.rb:42:in `start`'])

      elog({ message: 'Startup failed', exception: error }, log_src, lvl_error)

      content = File.read(log_file)
      entry = JSON.parse(content.strip.split("\n").last)

      expect(entry['severity']).to eq('ERROR')
      expect(entry['message']).to include('Startup failed')
      expect(entry['exception']).to be_a(Hash)
      expect(entry['exception']['class']).to eq('StandardError')

      expect(entry['exception']['message']).to include('[REDACTED]')
      expect(entry['exception']['message']).not_to include('hunter2')
    end
  end
end
