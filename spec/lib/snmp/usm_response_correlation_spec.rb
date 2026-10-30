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

  let(:packet) { 'packet decoded by the test double' }
  let(:engine_id) { ['000000000000000000000002'].pack('H*') }
  let(:response) { SNMP::Response.new(123, SNMP::VarBindList.new([])) }

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
      security_flags: 1,
      engine_id: engine_id,
      engine_boots: 1,
      engine_time: 10,
      pdu: response
    )
  end

  before do
    allow(usm).to receive(:decode_message).with(packet).and_return(message)
  end

  %i[process_discovery_response process_response].each do |method_name|
    describe "##{method_name}" do
      before do
        if method_name == :process_discovery_response
          allow(message).to receive(:pdu).and_return(report)
          allow(message).to receive(:security_flags).and_return(0)
        end
      end

      it 'ignores a mismatched message ID without synchronizing engine state' do
        expect(usm).not_to receive(:synchronize_engine)

        result = usm.public_send(
          method_name,
          packet,
          expected_message_id: 999,
          expected_request_id: 123
        )

        expect(result).to be_nil
        expect(usm.engine_known?).to be(false)
      end

      it 'ignores a mismatched request ID without synchronizing engine state' do
        expect(usm).not_to receive(:synchronize_engine)

        result = usm.public_send(
          method_name,
          packet,
          expected_message_id: 456,
          expected_request_id: 999
        )

        expect(result).to be_nil
        expect(usm.engine_known?).to be(false)
      end

      it 'synchronizes engine state for a matching response' do
        expect(usm).to receive(:synchronize_engine)
          .with(engine_id, 1, 10)
          .and_call_original

        result = usm.public_send(
          method_name,
          packet,
          expected_message_id: 456,
          expected_request_id: 123
        )

        expect(result).to eq(message)
        expect(usm.engine_known?).to be(true)
      end
    end
  end
end
