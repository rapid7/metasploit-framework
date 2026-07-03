# frozen_string_literal: true

require 'msf/core/mcp'
require 'stringio'
require 'json'

RSpec.describe Msf::MCP::Logging::Sinks::Sanitizing do
  let(:stream) { StringIO.new }
  let(:inner_sink) { Msf::MCP::Logging::Sinks::JsonStream.new(stream) }
  let(:sink) { described_class.new(inner_sink) }
  let(:log_source) { Msf::MCP::LOG_SOURCE }

  # Helper: parse the last JSON log entry from the stream
  def last_log_entry
    stream.rewind
    lines = stream.read.strip.split("\n")
    JSON.parse(lines.last)
  end

  describe '#log' do
    it 'delegates to the inner sink' do
      sink.log(:info, 'mcp', 0, 'hello')
      expect(last_log_entry['message']).to include('hello')
    end

    it 'passes severity, source, and level through' do
      sink.log(:error, 'mcp', 2, 'test')
      entry = last_log_entry
      expect(entry['severity']).to eq('ERROR')
      expect(entry['source']).to eq('mcp')
      expect(entry['level']).to eq('2')
    end

    it 'passes through innocuous messages unchanged' do
      sink.log(:info, 'mcp', 0, 'connected to host')
      expect(last_log_entry['message']).to include('connected to host')
    end
  end

  describe '#cleanup' do
    it 'delegates cleanup to the inner sink' do
      expect(inner_sink).to receive(:cleanup)
      sink.cleanup
    end
  end

  describe 'string sanitization' do
    it 'redacts password key-value pairs' do
      sink.log(:info, 'mcp', 0, 'password: hunter2')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('hunter2')
    end

    it 'redacts password with equals sign' do
      sink.log(:info, 'mcp', 0, 'password=s3cret')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('s3cret')
    end

    it 'redacts token key-value pairs' do
      sink.log(:info, 'mcp', 0, 'token=abc123xyz')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('abc123xyz')
    end

    it 'redacts bearer tokens' do
      sink.log(:info, 'mcp', 0, 'bearer eyJhbGci.payload.sig')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('eyJhbGci.payload.sig')
    end

    it 'redacts token header style' do
      sink.log(:info, 'mcp', 0, 'token abc123def')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('abc123def')
    end

    it 'redacts API keys' do
      sink.log(:info, 'mcp', 0, 'api_key=sk_live_1234567890')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('sk_live_1234567890')
    end

    it 'redacts secret keys' do
      sink.log(:info, 'mcp', 0, 'secret_key: my_secret_value')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('my_secret_value')
    end

    it 'redacts credential values' do
      sink.log(:info, 'mcp', 0, 'credential=admin_cred')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('admin_cred')
    end

    it 'redacts auth values' do
      sink.log(:info, 'mcp', 0, 'auth: some_auth_value')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('some_auth_value')
    end

    it 'is case-insensitive' do
      sink.log(:info, 'mcp', 0, 'PASSWORD: upper_case_secret')
      msg = last_log_entry['message']
      expect(msg).to include('[REDACTED]')
      expect(msg).not_to include('upper_case_secret')
    end

    it 'does not redact non-sensitive strings' do
      sink.log(:info, 'mcp', 0, 'Module loaded: exploit/windows/smb/ms17_010')
      expect(last_log_entry['message']).to eq('Module loaded: exploit/windows/smb/ms17_010')
    end
  end

  describe 'hash sanitization' do
    it 'redacts scalar values under sensitive keys' do
      msg = { message: 'test', context: { password: 'secret123', host: 'localhost' } }
      sink.log(:info, 'mcp', 0, msg)
      ctx = last_log_entry['context']

      expect(ctx['password']).to eq('[REDACTED]')
      expect(ctx['host']).to eq('localhost')
    end

    it 'redacts all SENSITIVE_KEYS patterns' do
      %w[password token secret api_key api_secret credential auth_token bearer access_token private_key].each do |key|
        stream.truncate(0)
        stream.rewind
        msg = { message: 'test', context: { key.to_sym => 'sensitive_value' } }
        sink.log(:info, 'mcp', 0, msg)
        ctx = last_log_entry['context']

        expect(ctx[key]).to eq('[REDACTED]'), "Expected #{key} to be redacted"
      end
    end

    it 'recurses into Hash values under sensitive keys' do
      msg = { message: 'test', context: { token: { password: 'deep_secret', safe: 'visible' } } }
      sink.log(:info, 'mcp', 0, msg)
      ctx = last_log_entry['context']

      # Hash under sensitive key is recursed, not replaced with REDACTED
      expect(ctx['token']).to be_a(Hash)
      expect(ctx['token']['password']).to eq('[REDACTED]')
      expect(ctx['token']['safe']).to eq('visible')
    end

    it 'recurses into Array values under sensitive keys' do
      msg = { message: 'test', context: { token: ['value1', 'password: secret'] } }
      sink.log(:info, 'mcp', 0, msg)
      ctx = last_log_entry['context']

      expect(ctx['token']).to be_an(Array)
      # String elements in the array get pattern-based sanitization
      expect(ctx['token'][1]).to include('[REDACTED]')
      expect(ctx['token'][1]).not_to include('secret')
    end

    it 'recurses into non-sensitive hash values' do
      msg = { message: 'test', context: { data: { password: 'nested_secret' } } }
      sink.log(:info, 'mcp', 0, msg)
      ctx = last_log_entry['context']

      expect(ctx['data']['password']).to eq('[REDACTED]')
    end

    it 'passes through non-string/hash/array types' do
      msg = { message: 'test', context: { count: 42, enabled: true, value: nil } }
      sink.log(:info, 'mcp', 0, msg)
      ctx = last_log_entry['context']

      expect(ctx['count']).to eq(42)
      expect(ctx['enabled']).to be true
      expect(ctx['value']).to be_nil
    end

    it 'sanitizes strings in arrays' do
      msg = { message: 'test', context: { items: ['safe', 'password=secret', 'also safe'] } }
      sink.log(:info, 'mcp', 0, msg)
      items = last_log_entry['context']['items']

      expect(items[0]).to eq('safe')
      expect(items[1]).to include('[REDACTED]')
      expect(items[1]).not_to include('secret')
      expect(items[2]).to eq('also safe')
    end
  end

  describe 'exception handling' do
    let(:error) do
      StandardError.new('password=s3cret in message').tap do |e|
        e.set_backtrace([
          '/opt/metasploit-framework/lib/msf/core/mcp/server.rb:42:in `start`',
          '/opt/metasploit-framework/lib/msf/core/mcp/application.rb:100:in `run`',
          '/home/user/lib/custom/code.rb:10:in `call`',
          'line4', 'line5', 'line6'
        ])
      end
    end

    it 'formats Exception as structured hash' do
      msg = { message: 'error occurred', exception: error }
      sink.log(:error, 'mcp', 0, msg)
      ex = last_log_entry['exception']

      expect(ex['class']).to eq('StandardError')
      expect(ex['message']).to be_a(String)
    end

    it 'sanitizes the exception message' do
      msg = { message: 'error occurred', exception: error }
      sink.log(:error, 'mcp', 0, msg)
      ex = last_log_entry['exception']

      expect(ex['message']).to include('[REDACTED]')
      expect(ex['message']).not_to include('s3cret')
    end

    context 'at DEBUG log level' do
      before do
        deregister_log_source(log_source) if log_source_registered?(log_source)
        register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new('/dev/null'), Rex::Logging::LEV_3)
      end

      after do
        deregister_log_source(log_source) if log_source_registered?(log_source)
      end

      it 'includes backtrace' do
        msg = { message: 'error', exception: error }
        sink.log(:error, 'mcp', 0, msg)
        ex = last_log_entry['exception']

        expect(ex['backtrace']).to be_an(Array)
      end

      it 'limits backtrace to 5 frames' do
        msg = { message: 'error', exception: error }
        sink.log(:error, 'mcp', 0, msg)
        ex = last_log_entry['exception']

        expect(ex['backtrace'].length).to eq(5)
      end

      it 'strips install path prefix from backtrace frames' do
        msg = { message: 'error', exception: error }
        sink.log(:error, 'mcp', 0, msg)
        bt = last_log_entry['exception']['backtrace']

        expect(bt[0]).to start_with('lib/msf/')
        expect(bt[0]).not_to include('/opt/metasploit-framework/')
      end

      it 'sanitizes backtrace strings containing sensitive patterns' do
        error_with_sensitive_bt = StandardError.new('fail').tap do |e|
          e.set_backtrace(['lib/msf/core/mcp/server.rb:42:in `token=abc123`'])
        end
        msg = { message: 'error', exception: error_with_sensitive_bt }
        sink.log(:error, 'mcp', 0, msg)
        bt = last_log_entry['exception']['backtrace']

        expect(bt[0]).to include('[REDACTED]')
        expect(bt[0]).not_to include('abc123')
      end
    end

    context 'below DEBUG log level' do
      before do
        deregister_log_source(log_source) if log_source_registered?(log_source)
        register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new('/dev/null'), Rex::Logging::LEV_0)
      end

      after do
        deregister_log_source(log_source) if log_source_registered?(log_source)
      end

      it 'omits backtrace' do
        msg = { message: 'error', exception: error }
        sink.log(:error, 'mcp', 0, msg)
        ex = last_log_entry['exception']

        expect(ex).not_to have_key('backtrace')
      end
    end

    it 'handles exception with nil backtrace' do
      no_bt = RuntimeError.new('no trace')
      msg = { message: 'error', exception: no_bt }
      sink.log(:error, 'mcp', 0, msg)
      ex = last_log_entry['exception']

      expect(ex['class']).to eq('RuntimeError')
      expect(ex['message']).to eq('no trace')
    end

    it 'passes non-Exception :exception values through after sanitization' do
      msg = { message: 'error', exception: 'password=oops' }
      sink.log(:error, 'mcp', 0, msg)

      expect(last_log_entry['exception']).to include('[REDACTED]')
      expect(last_log_entry['exception']).not_to include('oops')
    end
  end
end
