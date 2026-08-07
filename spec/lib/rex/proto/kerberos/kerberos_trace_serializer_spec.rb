# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/kerberos/kerberos_trace_serializer'

RSpec.describe Rex::Proto::Kerberos::KerberosTraceSerializer do
  subject(:serializer) { described_class.new }

  describe '#serialize' do
    it 'serializes Kerberos message types and redacts binary values' do
      message = double(
        'Kerberos message',
        attributes: %i[msg_type payload],
        msg_type: Rex::Proto::Kerberos::Model::AP_REQ,
        payload: "\x00\xff".b
      )

      expect(serializer.serialize(message, redact_binary: true)).to eq(
        'msg_type' => '14 (AP-REQ)',
        'payload' => '[binary 2 bytes]'
      )
    end

    it 'includes binary contents when redaction is disabled' do
      message = double(
        'Kerberos message',
        attributes: [:payload],
        payload: "\x00\xff".b
      )

      expect(serializer.serialize(message, redact_binary: false)).to eq(
        'payload' => '[binary 2 bytes: 00ff]'
      )
    end
  end

  describe '#encryption_type_name' do
    it 'returns UNKNOWN for unsupported encryption types' do
      expect(serializer.encryption_type_name(-1)).to eq('UNKNOWN')
    end
  end
end
