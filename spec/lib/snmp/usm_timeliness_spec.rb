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

  let(:engine_id) { ['000000000000000000000002'].pack('H*') }
  let(:packet) { 'packet decoded by the test double' }
  let(:response) { SNMP::Response.new(123, SNMP::VarBindList.new([])) }

  let(:message) do
    instance_double(
      SNMP::V3Message,
      message_id: 456,
      pdu: response,
      engine_id: engine_id,
      engine_boots: 5,
      engine_time: 1000,
      authenticated?: true,
      encrypted?: false,
      report?: false
    )
  end

  before do
    usm.send(:synchronize_engine, engine_id, 5, 1000)
    allow(usm).to receive(:current_engine_time).and_return(1000)
    allow(usm).to receive(:decode_message).with(packet).and_return(message)
  end

  def process_message
    usm.process_response(
      packet,
      expected_message_id: 456,
      expected_request_id: 123
    )
  end

  describe '#process_response' do
    it 'rejects an older engine boot counter' do
      allow(message).to receive(:engine_boots).and_return(4)
      expect(usm).not_to receive(:synchronize_engine)

      expect { process_message }.to raise_error(SNMP::AuthenticationError)
    end

    it 'rejects a response 151 seconds behind the estimated engine time' do
      allow(message).to receive(:engine_time).and_return(849)
      expect(usm).not_to receive(:synchronize_engine)

      expect { process_message }.to raise_error(SNMP::AuthenticationError)
    end

    it 'accepts a response exactly 150 seconds behind without changing state' do
      allow(message).to receive(:engine_time).and_return(850)
      expect(usm).not_to receive(:synchronize_engine)

      expect(process_message).to eq(message)
    end

    it 'accepts an in-window reordered response without changing state' do
      allow(message).to receive(:engine_time).and_return(950)
      expect(usm).not_to receive(:synchronize_engine)

      expect(process_message).to eq(message)
    end

    it 'accepts a higher boot counter with a reset engine time' do
      allow(message).to receive(:engine_boots).and_return(6)
      allow(message).to receive(:engine_time).and_return(10)

      expect(usm).to receive(:synchronize_engine)
        .with(engine_id, 6, 10)
        .and_call_original

      expect(process_message).to eq(message)
    end

    it 'updates state for a newer engine time' do
      allow(message).to receive(:engine_time).and_return(1100)

      expect(usm).to receive(:synchronize_engine)
        .with(engine_id, 5, 1100)
        .and_call_original

      expect(process_message).to eq(message)
    end

    it 'rejects a different engine ID without changing state' do
      allow(message).to receive(:engine_id).and_return('different engine')
      expect(usm).not_to receive(:synchronize_engine)

      expect { process_message }.to raise_error(SNMP::AuthenticationError)
    end

    it 'rejects an exhausted engine boot counter' do
      allow(message).to receive(:engine_boots).and_return(2_147_483_647)
      expect(usm).not_to receive(:synchronize_engine)

      expect { process_message }.to raise_error(SNMP::AuthenticationError)
    end
  end
end
