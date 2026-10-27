require 'spec_helper'
require 'snmp'

RSpec.describe SNMP::UserBasedSecurityModel do
  let(:engine_id) { ['000000000000000000000002'].pack('H*') }

  let(:configuration) do
    {
      username: 'testuser',
      security_level: 'authNoPriv',
      auth_protocol: 'SHA1',
      auth_password: 'maplesyrup',
      priv_protocol: 'AES',
      priv_password: '',
      context_name: ''
    }
  end

  subject(:usm) { described_class.new(**configuration) }

  describe 'Report request ID zero' do
    let(:packet) { 'packet decoded by the test double' }

    let(:report) do
      SNMP::Report.new(
        0,
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
        pdu: report
      )
    end

    before do
      allow(usm).to receive(:decode_message)
        .with(packet).and_return(message)
    end

    %i[process_discovery_response process_response].each do |method_name|
      context "with #{method_name}" do
        before do
          if method_name == :process_discovery_response
            allow(message).to receive(:security_flags).and_return(0)
          end
        end

        it 'accepts a Report with request ID zero and a matching message ID' do
          expect(usm).to receive(:synchronize_engine)
            .with(engine_id, 1, 10).and_call_original

          result = usm.public_send(
            method_name,
            packet,
            expected_message_id: 456,
            expected_request_id: 123
          )

          expect(result).to eq(message)
          expect(usm.engine_known?).to be(true)
        end

        it 'still ignores a Report with a mismatched message ID' do
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
      end
    end

    it 'does not allow request ID zero for an ordinary Response' do
      allow(message).to receive(:pdu)
        .and_return(SNMP::Response.new(0, SNMP::VarBindList.new([])))
      expect(usm).not_to receive(:synchronize_engine)

      result = usm.process_response(
        packet,
        expected_message_id: 456,
        expected_request_id: 123
      )

      expect(result).to be_nil
      expect(usm.engine_known?).to be(false)
    end
  end

  describe 'reflected request packets' do
    %w[authNoPriv authPriv].each do |security_level|
      context "with #{security_level}" do
        let(:configuration) do
          super().merge(
            security_level: security_level,
            priv_password: 'maplesyrup'
          )
        end

        before do
          usm.send(:synchronize_engine, engine_id, 1, 10)
        end

        [SNMP::GetRequest, SNMP::SetRequest].each do |pdu_class|
          it "rejects an encoded #{pdu_class} without synchronizing engine state" do
            request = pdu_class.new(123, SNMP::VarBindList.new([]))
            packet = usm.request_message(request, 456, 8000)

            expect(usm).not_to receive(:synchronize_engine)

            expect do
              usm.process_response(
                packet,
                expected_message_id: 456,
                expected_request_id: 123
              )
            end.to raise_error(
              SNMP::InvalidSecurityParameters,
              /requires a Response or Report PDU/
            )
          end
        end
      end
    end
  end
end

RSpec.describe SNMP::Manager do
  subject(:manager) { described_class.allocate }

  let(:transport) { instance_double(SNMP::RexUDPTransport) }
  let(:usm) { instance_double(SNMP::UserBasedSecurityModel) }
  let(:request) { SNMP::GetRequest.new(123, SNMP::VarBindList.new([])) }

  let(:message) do
    instance_double(SNMP::V3Message)
  end

  before do
    manager.instance_variable_set(:@transport, transport)
    manager.instance_variable_set(:@usm, usm)
    manager.instance_variable_set(:@max_bytes, 8000)
  end

  describe '#receive_v3_message' do
    it 'passes both expected identifiers to USM' do
      expect(transport).to receive(:recv).with(8000)
                                         .and_return('response packet')
      expect(usm).to receive(:process_response).with(
        'response packet',
        expected_message_id: 456,
        expected_request_id: 123
      ).and_return(message)

      expect(manager.send(:receive_v3_message, request, 456))
        .to eq(message)
    end

    it 'continues receiving when USM ignores an unrelated packet' do
      expect(transport).to receive(:recv).with(8000).ordered
                                         .and_return('unrelated packet')
      expect(usm).to receive(:process_response).with(
        'unrelated packet',
        expected_message_id: 456,
        expected_request_id: 123
      ).ordered.and_return(nil)

      expect(transport).to receive(:recv).with(8000).ordered
                                         .and_return('matching packet')
      expect(usm).to receive(:process_response).with(
        'matching packet',
        expected_message_id: 456,
        expected_request_id: 123
      ).ordered.and_return(message)

      expect(manager.send(:receive_v3_message, request, 456))
        .to eq(message)
    end
  end
end
