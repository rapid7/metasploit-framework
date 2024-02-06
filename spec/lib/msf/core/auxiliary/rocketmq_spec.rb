require 'spec_helper'

RSpec.describe Msf::Auxiliary::Rocketmq do
  subject do
    mod = Msf::Auxiliary.new
    mod.extend(Msf::Exploit::Remote::Tcp)
    mod.extend(Msf::Auxiliary::Rocketmq)
    mod
  end

  let(:mock_name_server_response) do
    "\x00\x00\x00\xC7\x00\x00\x00\xC3{\"code\":105,\"extFields\":{\"Signature\":\"/u5P/wZUbhjanu4LM/UzEdo2u2I=\",\"topic\":\"TBW102\",\"AccessKey\":\"rocketmq2\"},\"flag\":0,\"language\":\"JAVA\",\"opaque\":1,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":401}".b
  end

  let(:expected_name_server_response) do
    "\x00\x00\x01a\x00\x00\x00_{\"code\":0,\"flag\":1,\"language\":\"JAVA\",\"opaque\":1,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":403}{\"brokerDatas\":[{\"brokerAddrs\":{\"0\":\"172.16.199.135:10911\"},\"brokerName\":\"DESKTOP-8ATHH6O\",\"cluster\":\"DefaultCluster\"}],\"filterServerTable\":{},\"queueDatas\":[{\"brokerName\":\"DESKTOP-8ATHH6O\",\"perm\":7,\"readQueueNums\":8,\"topicSysFlag\":0,\"writeQueueNums\":8}]}".b
  end

  let(:expected_parsed_data_response) do
    {
      'brokerDatas' => [
        {
          'brokerAddrs' => {
            '0' => '172.16.199.135:10911'
          },
          'brokerName' => 'DESKTOP-8ATHH6O',
          'cluster' => 'DefaultCluster'
        }
      ],
      'version' => 'V4.9.5'
    }
  end

  let(:mock_sock) { double :'Rex::Socket::Tcp', send: nil, recv: expected_name_server_response, close: nil, shutdown: nil }

  before(:each) do
    allow(subject).to receive(:connect).and_return(mock_sock)
    allow(subject).to receive(:sock).and_return(mock_sock)
  end

  describe '#get_rocketmq_version' do
    context 'correctly looks up id 401 as V4.9.4' do
      it 'returns that version' do
        expect(subject.get_rocketmq_version(401)).to eql('V4.9.4')
      end
    end

    context 'correctly looks up id 99999 as UNKNOWN.VERSION.ID.99999' do
      it 'returns that version' do
        expect(subject.get_rocketmq_version(99999)).to eql('UNKNOWN.VERSION.ID.99999')
      end
    end
  end

  describe '#send_version_request' do
    it 'returns version info' do
      expect(mock_sock).to receive(:send).with(mock_name_server_response, 0)
      expect(subject.send_version_request).to eq(expected_name_server_response)
    end
  end

  describe '#parse_rocketmq_data' do
    it 'correctly parses the response from the name server into version and brokeDatas info' do
      expect(subject.parse_rocketmq_data(expected_name_server_response)).to eq(expected_parsed_data_response)
    end
  end

  describe '#get_broker_port' do
    it 'returns the broker port associated with the given rport in the name server response ' do
      expect(subject.get_broker_port(expected_parsed_data_response, '172.16.199.135')).to eq(10911)
    end

    it 'returns the default broker port when rhost is not found in the name server response' do
      expect(subject.get_broker_port(expected_parsed_data_response, '172.16.199.1', default_broker_port: 10000)).to eq(10000)
    end
  end
end