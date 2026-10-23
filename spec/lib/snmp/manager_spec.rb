require 'spec_helper'
require 'snmp'

RSpec.describe SNMP::Manager do
  subject(:manager) { described_class.allocate }

  let(:host) { '192.0.2.1' }
  let(:port) { 161 }
  let(:request) { SNMP::GetRequest.new(123, SNMP::VarBindList.new([])) }
  let(:response) { SNMP::Response.new(123, SNMP::VarBindList.new([])) }
  let(:transport) { instance_double(SNMP::RexUDPTransport) }
  let(:usm) { instance_double(SNMP::UserBasedSecurityModel) }

  before do
    manager.instance_variable_set(:@host, host)
    manager.instance_variable_set(:@port, port)
    manager.instance_variable_set(:@community, 'public')
    manager.instance_variable_set(:@config, { Host: host })
    manager.instance_variable_set(:@retries, 1)
    manager.instance_variable_set(:@timeout, 1)
    manager.instance_variable_set(:@max_bytes, 8000)
    manager.instance_variable_set(:@transport, transport)
    manager.instance_variable_set(:@usm, usm)
  end

  describe '#try_request' do
    context 'with SNMPv1 or SNMPv2c' do
      %i[SNMPv1 SNMPv2c].each do |version|
        it "uses the existing community request path for #{version}" do
          manager.instance_variable_set(:@snmp_version, version)

          expect(manager).not_to receive(:try_v3_request)
          expect(manager).to receive(:send_request)
            .with(request, 'public', host, port)
          # allow(manager).to receive(:receive_response).and_return(response)
          expect(manager).to receive(:get_response)
            .with(request)
            .and_return(response)

          expect(manager.send(:try_request, request)).to eq(response)
        end
      end
    end

    context 'with SNMPv3' do
      it 'delegates to the SNMPv3 request path' do
        manager.instance_variable_set(:@snmp_version, :SNMPv3)

        expect(manager).to receive(:try_v3_request)
          .with(request, host, port)
          .and_return(response)

        expect(manager.send(:try_request, request)).to eq(response)
      end
    end
  end

  describe '#try_v3_request' do
    let(:message) do
      instance_double(SNMP::V3Message, report?: false, pdu: response)
    end

    before do
      allow(usm).to receive(:engine_known?).and_return(true)
      allow(usm).to receive(:request_message).and_return('encoded request')
      allow(transport).to receive(:send)
    end

    it 'discovers the engine when it is unknown' do
      allow(usm).to receive(:engine_known?).and_return(false)

      expect(manager).to receive(:discover_v3_engine).with(host, port)
      allow(manager).to receive(:receive_v3_message).and_return(message)

      expect(manager.send(:try_v3_request, request, host, port)).to eq(response)
    end

    it 'returns a successful response without rediscovery' do
      expect(manager).not_to receive(:discover_v3_engine)
      allow(manager).to receive(:receive_v3_message).and_return(message)

      expect(manager.send(:try_v3_request, request, host, port)).to eq(response)
    end

    it 'retries after a timeout and returns the subsequent response' do
      attempts = 0
      allow(manager).to receive(:receive_v3_message) do
        attempts += 1
        raise Timeout::Error if attempts == 1

        message
      end
      expect(transport).to receive(:send)
        .with('encoded request', host, port).twice

      expect(manager.send(:try_v3_request, request, host, port)).to eq(response)
    end

    it 'raises RequestTimeout after exhausting retries' do
      allow(manager).to receive(:receive_v3_message).and_raise(Timeout::Error)
      expect(transport).to receive(:send)
        .with('encoded request', host, port).twice

      expect do
        manager.send(:try_v3_request, request, host, port)
      end.to raise_error(SNMP::RequestTimeout)
    end

    it 'raises SecurityError for a nonrecoverable report' do
      allow(message).to receive(:report?).and_return(true)
      allow(manager).to receive(:receive_v3_message).and_return(message)
      allow(usm).to receive(:resynchronization_report?)
        .with(response).and_return(false)
      allow(usm).to receive(:report_description)
        .with(response).and_return('unknown username')

      expect do
        manager.send(:try_v3_request, request, host, port)
      end.to raise_error(SNMP::SecurityError, /unknown username/)
    end

    it 'limits rediscovery to one attempt for repeated recoverable reports' do
      allow(message).to receive(:report?).and_return(true)
      allow(manager).to receive(:receive_v3_message).and_return(message)
      allow(usm).to receive(:resynchronization_report?)
        .with(response).and_return(true)
      allow(usm).to receive(:report_description)
        .with(response).and_return('not in time window')

      expect(usm).to receive(:forget_engine).once
      expect(manager).to receive(:discover_v3_engine).with(host, port).once

      expect do
        manager.send(:try_v3_request, request, host, port)
      end.to raise_error(SNMP::SecurityError, /not in time window/)
    end
  end
end
