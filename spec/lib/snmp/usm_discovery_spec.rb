require 'spec_helper'
require 'snmp'

RSpec.describe SNMP::UserBasedSecurityModel do
  subject(:usm) do
    described_class.new(
      username: 'testuser',
      security_level: 'authNoPriv',
      auth_protocol: 'SHA1',
      auth_password: 'maplesyrup',
      priv_protocol: 'AES',
      priv_password: '',
      context_name: ''
    )
  end

  let(:packet) { 'discovery packet decoded by the test double' }
  let(:engine_id) { ['000000000000000000000002'].pack('H*') }

  let(:report) do
    SNMP::Report.new(
      123,
      SNMP::VarBindList.new([
        SNMP::VarBind.new(
          '1.3.6.1.6.3.15.1.1.4.0',
          SNMP::Counter32.new(1)
        )
      ])
    )
  end

  let(:message) do
    SNMP::V3Message.new(
      message_id: 456,
      security_flags: 0,
      engine_id: engine_id,
      engine_boots: 5,
      engine_time: 1000,
      pdu: report
    )
  end

  before do
    allow(usm).to receive(:decode_message).with(packet).and_return(message)
  end

  def process_discovery
    usm.process_discovery_response(
      packet,
      expected_message_id: 456,
      expected_request_id: 123
    )
  end

  describe '#process_discovery_response' do
    it 'accepts a matching unknown-engine Report and records engine state' do
      expect(process_discovery).to eq(message)
      expect(usm.engine_known?).to be(true)
    end

    it 'rejects an ordinary Response PDU without recording engine state' do
      response = SNMP::Response.new(123, SNMP::VarBindList.new([]))
      allow(message).to receive(:pdu).and_return(response)
      expect(usm).not_to receive(:synchronize_engine)

      expect do
        process_discovery
      end.to raise_error(SNMP::InvalidSecurityParameters)
    end

    it 'rejects an empty Report without recording engine state' do
      empty_report = SNMP::Report.new(123, SNMP::VarBindList.new([]))
      allow(message).to receive(:pdu).and_return(empty_report)
      expect(usm).not_to receive(:synchronize_engine)

      expect do
        process_discovery
      end.to raise_error(SNMP::InvalidSecurityParameters)
    end

    it 'rejects an unrelated Report without recording engine state' do
      unrelated_report = SNMP::Report.new(
        123,
        SNMP::VarBindList.new([
          SNMP::VarBind.new(
            '1.3.6.1.6.3.15.1.1.3.0',
            SNMP::Counter32.new(1)
          )
        ])
      )
      allow(message).to receive(:pdu).and_return(unrelated_report)
      expect(usm).not_to receive(:synchronize_engine)

      expect do
        process_discovery
      end.to raise_error(SNMP::InvalidSecurityParameters)
    end

    it 'rejects an empty engine ID without recording engine state' do
      allow(message).to receive(:engine_id).and_return('')
      expect(usm).not_to receive(:synchronize_engine)

      expect do
        process_discovery
      end.to raise_error(SNMP::InvalidSecurityParameters)
    end
  end
end
