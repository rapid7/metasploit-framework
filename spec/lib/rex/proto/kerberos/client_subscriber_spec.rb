# -*- coding: binary -*-

require 'spec_helper'

require 'stringio'

# Minimal in-memory socket used to exercise the Rex Kerberos client.
class TestKerberosStringIO < StringIO
  def put(data)
    write(data)
  end

  def get_once(length, _timeout = 10)
    read(length)
  end
end

RSpec.describe Rex::Proto::Kerberos::Client do
  let(:rhost) { '127.0.0.1' }
  let(:rport) { 88 }

  before(:example) do
    allow(Rex::Socket::Tcp).to receive(:create) do
      TestKerberosStringIO.new('', 'w+b')
    end
  end

  describe '#send_request' do
    let(:subscriber) { instance_double(Rex::Proto::Kerberos::KerberosSubscriber, on_request: nil) }
    let(:request) { instance_double('KerberosRequest', encode: 'abc') }

    subject(:client) do
      described_class.new(
        host: rhost,
        port: rport,
        subscriber: subscriber
      )
    end

    it 'notifies the subscriber before sending the request' do
      expect(subscriber).to receive(:on_request).with(
        request,
        raw: 'abc',
        context: { peer: "#{rhost}:#{rport}", protocol: 'tcp' }
      )

      client.send_request(request)
    end
  end

  describe '#recv_response' do
    let(:subscriber) { instance_double(Rex::Proto::Kerberos::KerberosSubscriber, on_response: nil) }
    let(:res_error) do
      "\x00\x00\x00\x8f\x7e\x81\x8c\x30\x81\x89\xa0\x03\x02\x01\x05\xa1" \
      "\x03\x02\x01\x1e\xa4\x11\x18\x0f\x32\x30\x31\x34\x31\x32\x31\x39" \
      "\x31\x38\x30\x35\x30\x33\x5a\xa5\x04\x02\x02\x51\x89\xa6\x03\x02" \
      "\x01\x18\xa9\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c" \
      "\xaa\x1f\x30\x1d\xa0\x03\x02\x01\x01\xa1\x16\x30\x14\x1b\x06\x6b" \
      "\x72\x62\x74\x67\x74\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41" \
      "\x4c\xac\x30\x04\x2e\x30\x2c\x30\x16\xa1\x03\x02\x01\x0b\xa2\x0f" \
      "\x04\x0d\x30\x0b\x30\x09\xa0\x03\x02\x01\x17\xa1\x02\x04\x00\x30" \
      "\x12\xa1\x03\x02\x01\x13\xa2\x0b\x04\x09\x30\x07\x30\x05\xa0\x03" \
      "\x02\x01\x17"
    end

    subject(:client) do
      described_class.new(
        host: rhost,
        port: rport,
        subscriber: subscriber
      )
    end

    it 'notifies the subscriber after decoding the response' do
      client.connect
      client.connection.write(res_error)
      client.connection.seek(0)

      expect(subscriber).to receive(:on_response).with(
        an_instance_of(Rex::Proto::Kerberos::Model::KrbError),
        raw: res_error.byteslice(4, res_error.bytesize - 4),
        context: { peer: "#{rhost}:#{rport}", protocol: 'tcp' }
      )

      client.recv_response
    end
  end
end
