require 'spec_helper'

RSpec.describe Msf::Payload::Python do
  describe '#create_exec_stub' do
    let(:python_code) { 'print("hello world");' }

    it 'does not include double quotes' do
      # some usages of this method make this assumption and breaking it would create problems
      expect(described_class.create_exec_stub(python_code)).to_not include('"')
    end

    it 'does not include spaces' do
      expect(described_class.create_exec_stub(python_code)).to_not include(' ')
    end

    it 'does not include semicolons' do
      # this makes sure that the result is a single expression, not a series of statements
      expect(described_class.create_exec_stub(python_code)).to_not include(';')
    end
  end

  describe '.ssl_wrap_socket_stub' do
    subject(:stub) { described_class.ssl_wrap_socket_stub('so', 's') }

    it 'returns exactly three lines' do
      expect(stub.lines.length).to eq(3)
    end

    it 'begins with its own import ssl so callers need not pre-import ssl under any particular name' do
      expect(stub.lines.first).to eq("import ssl\n")
    end

    it 'opens with a try branch that uses the legacy ssl.wrap_socket' do
      expect(stub.lines[1]).to match(/^try:s=ssl\.wrap_socket\(so\)/)
    end

    it 'falls back via a lambda to avoid leaking a temporary variable into surrounding scope' do
      expect(stub.lines.last).to include('lambda c:')
    end

    it 'contains the PROTOCOL_TLS_CLIENT getattr chain for broad version coverage' do
      expect(stub).to include("getattr(ssl,'PROTOCOL_TLS_CLIENT',getattr(ssl,'PROTOCOL_TLS',ssl.PROTOCOL_SSLv23))")
    end

    it 'sets check_hostname before verify_mode to satisfy the Python >=3.4 ordering constraint' do
      expect(stub.index('check_hostname')).to be < stub.index('verify_mode')
    end

    it 'assigns the wrapped socket to the out_var' do
      expect(stub.lines.last).to match(/^except:s=/)
    end

    context 'when in_var and out_var are the same (in-place wrap)' do
      subject(:stub) { described_class.ssl_wrap_socket_stub('so') }

      it 'wraps so in place' do
        expect(stub).to include('so=ssl.wrap_socket(so)')
        expect(stub).to include('c.wrap_socket(so)')
      end

      it 'passes the original in_var to the lambda wrap_socket call' do
        # the lambda arg (last wrap_socket call) must reference the raw socket, not the context
        expect(stub.lines.last).to include('c.wrap_socket(so)')
      end
    end

    context 'with an indent prefix' do
      subject(:stub) { described_class.ssl_wrap_socket_stub('so', 's', indent: "\t\t") }

      it 'prefixes all three lines with the indent' do
        expect(stub.lines).to all(start_with("\t\t"))
      end
    end
  end
end
