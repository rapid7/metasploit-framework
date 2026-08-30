require 'spec_helper'
require 'json'
require 'metasploit/framework/data_service/remote/http/core'

RSpec.describe ResponseDataHelper do
  subject do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin
    end
    klass.new
  end

  let(:host_hash) do
    {
      id: 1,
      created_at: '2021-04-12T15:36:51.130Z',
      address: '127.0.0.1',
      mac: nil,
      comm: '',
      name: 'localhost',
      state: 'alive',
      os_name: 'Unknown',
      os_flavor: nil,
      os_sp: nil,
      os_lang: nil,
      arch: nil,
      workspace_id: 1,
      updated_at: '2021-04-12T15:36:51.155Z',
      purpose: 'device',
      info: nil,
      comments: nil,
      scope: nil,
      virtual_host: nil,
      note_count: 0,
      vuln_count: 0,
      service_count: 5,
      host_detail_count: 0,
      exploit_attempt_count: 0,
      cred_count: 0,
      detected_arch: nil,
      os_family: nil
    }
  end
  let(:service_hash) do
    {
      id: 1,
      host_id: 1,
      created_at: '2021-04-12T15:36:51.146Z',
      port: 53,
      proto: 'tcp',
      state: 'open',
      name: 'domain',
      updated_at: '2021-04-12T15:36:51.146Z',
      info: '',
      host: host_hash
    }
  end

  describe '#json_to_mdm_object' do
    context 'when the json is a service object' do
      let(:response_body_json) do
        JSON.pretty_generate({ data: [service_hash] })
      end

      let(:response_wrapper) do
        instance_double(
          Metasploit::Framework::DataService::RemoteHTTPDataService::SuccessResponse,
          response_body: response_body_json
        )
      end

      before(:each) do
        allow(response_wrapper).to receive(:is_a?).with(Metasploit::Framework::DataService::RemoteHTTPDataService::SuccessResponse).and_return(true)
      end

      it 'converts the service object successfully' do
        expected_service_attributes = {
          id: 1,
          host_id: 1,
          created_at: Time.zone.parse('2021-04-12T15:36:51.146Z'),
          port: 53,
          proto: 'tcp',
          state: 'open',
          name: 'domain',
          updated_at: Time.zone.parse('2021-04-12T15:36:51.146Z'),
          info: ''
        }

        result = subject.json_to_mdm_object(response_wrapper, 'Mdm::Service')
        expect(result.size).to be(1)
        expect(result.first.class).to eq Mdm::Service
        expect(result.first).to have_attributes(expected_service_attributes)
      end

      it 'converts the service relation host object successfully' do
        expected_host_attributes = {
          id: 1,
          created_at: Time.zone.parse('2021-04-12T15:36:51.130Z'),
          address: '127.0.0.1',
          mac: nil,
          comm: '',
          name: 'localhost',
          state: 'alive',
          os_name: 'Unknown',
          os_flavor: nil,
          os_sp: nil,
          os_lang: nil,
          arch: nil,
          workspace_id: 1,
          updated_at: Time.zone.parse('2021-04-12T15:36:51.155Z'),
          purpose: 'device',
          info: nil,
          comments: nil,
          scope: nil,
          virtual_host: nil,
          note_count: 0,
          vuln_count: 0,
          service_count: 5,
          host_detail_count: 0,
          exploit_attempt_count: 0,
          cred_count: 0,
          detected_arch: nil,
          os_family: nil
        }

        service = subject.json_to_mdm_object(response_wrapper, 'Mdm::Service').first
        host = service.host
        expect(host.class).to eql(Mdm::Host)
        expect(host).to have_attributes(expected_host_attributes)
      end
    end
  end
end
