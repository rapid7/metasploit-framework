# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::KerberosLoggerSubscriber do
  include_context 'Msf::UIDriver'

  let(:mock_module) { instance_double(Msf::Exploit, datastore: mock_datastore) }

  subject(:subscriber) do
    capture_logging(mock_module)
    described_class.new(logger: mock_module)
  end

  let(:mock_datastore) do
    {
      'KerberosTicketTrace' => true
    }
  end

  let(:request) do
    build_kerberos_message(msg_type: Rex::Proto::Kerberos::Model::AS_REQ)
  end

  let(:response) do
    build_kerberos_message(msg_type: Rex::Proto::Kerberos::Model::AS_REP)
  end

  describe '#on_request' do
    let(:normal_request_output) do
      [
        '####################',
        '# Kerberos Request: AS-REQ',
        '####################',
        '%clr%bld%red{',
        '  "pvno": 5,',
        "  \"msg_type\": #{Rex::Proto::Kerberos::Model::AS_REQ},",
        '  "crealm": "EXAMPLE.LOCAL"',
        '}%clr'
      ]
    end

    context 'when KerberosTicketTrace is enabled' do
      it 'logs AS-REQ messages with default request color' do
        subscriber.on_request(request)

        expect(@output).to eq(normal_request_output)
      end
    end

    context 'when KerberosTicketTrace is disabled' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => false
        }
      end

      it 'does not log request data' do
        subscriber.on_request(request)

        expect(@output).to be_nil
      end
    end

    context 'when KerberosTicketTrace is unset' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => nil
        }
      end

      it 'does not log request data' do
        subscriber.on_request(request)

        expect(@output).to be_nil
      end
    end

    context 'when KerberosTicketTraceColors is set' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => 'blu/grn'
        }
      end

      it 'uses custom request color' do
        subscriber.on_request(request)

        expect(@output[3]).to eq('%clr%bld%blu{')
      end
    end

    context 'when KerberosTicketTraceColors is set to a single request color with trailing slash' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => 'yel/'
        }
      end

      it 'uses the configured request color' do
        subscriber.on_request(request)

        expect(@output[3]).to eq('%clr%bld%yel{')
      end
    end

    context 'when KerberosTicketTraceColors is set to response color only with a leading slash' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => '/yel'
        }
      end

      it 'logs request without color formatting' do
        subscriber.on_request(request)

        expect(@output[3]).to eq('%clr{')
      end
    end

    context 'when KerberosTicketTraceColors is set to slash only' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => '/'
        }
      end

      it 'logs request without color formatting' do
        subscriber.on_request(request)

        expect(@output[3]).to eq('%clr{')
      end
    end

    context 'when KerberosTicketTraceColors is set to a single color without slash' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => 'yel'
        }
      end

      it 'uses the configured request color' do
        subscriber.on_request(request)

        expect(@output[3]).to eq('%clr%bld%yel{')
      end
    end

    context 'when request type is unknown' do
      let(:request) do
        build_kerberos_message(msg_type: 999)
      end

      it 'logs request with UNKNOWN header' do
        subscriber.on_request(request)

        expect(@output).to include('# Kerberos Request: UNKNOWN (999)')
      end
    end
  end

  describe '#on_response' do
    let(:normal_response_output) do
      [
        '####################',
        '# Kerberos Response: AS-REP',
        '####################',
        '%clr%bld%blu{',
        '  "pvno": 5,',
        "  \"msg_type\": #{Rex::Proto::Kerberos::Model::AS_REP},",
        '  "crealm": "EXAMPLE.LOCAL"',
        '}%clr'
      ]
    end

    let(:nil_response_output) do
      [
        '####################',
        '# Kerberos Response: UNKNOWN',
        '####################',
        'No response received'
      ]
    end

    context 'when KerberosTicketTrace is enabled' do
      it 'logs AS-REP messages with default response color' do
        subscriber.on_response(response)

        expect(@output).to eq(normal_response_output)
      end

      it 'logs missing responses' do
        subscriber.on_response(nil)

        expect(@output).to eq(nil_response_output)
      end
    end

    context 'when KerberosTicketTraceColors is set' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => 'blu/grn'
        }
      end

      it 'uses custom response color' do
        subscriber.on_response(response)

        expect(@output[3]).to eq('%clr%bld%grn{')
      end
    end

    context 'when KerberosTicketTraceColors is set to a single request color with trailing slash' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => 'yel/'
        }
      end

      it 'logs response without color formatting' do
        subscriber.on_response(response)

        expect(@output[3]).to eq('%clr{')
      end
    end

    context 'when KerberosTicketTraceColors is set to response color only with a leading slash' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceColors' => '/yel'
        }
      end

      it 'uses the configured response color' do
        subscriber.on_response(response)

        expect(@output[3]).to eq('%clr%bld%yel{')
      end
    end
  end

  describe 'request message type mapping' do
    {
      Rex::Proto::Kerberos::Model::AS_REQ => 'AS-REQ',
      Rex::Proto::Kerberos::Model::TGS_REQ => 'TGS-REQ',
      Rex::Proto::Kerberos::Model::AP_REQ => 'AP-REQ',
      Rex::Proto::Kerberos::Model::KRB_ERROR => 'KRB-ERROR'
    }.each do |msg_type, msg_name|
      it "maps request msg_type #{msg_type} to #{msg_name}" do
        subscriber.on_request(build_kerberos_message(msg_type: msg_type))

        expect(@output).to include("# Kerberos Request: #{msg_name}")
      end
    end
  end

  describe 'response message type mapping' do
    {
      Rex::Proto::Kerberos::Model::AS_REP => 'AS-REP',
      Rex::Proto::Kerberos::Model::TGS_REP => 'TGS-REP',
      Rex::Proto::Kerberos::Model::AP_REP => 'AP-REP',
      Rex::Proto::Kerberos::Model::KRB_ERROR => 'KRB-ERROR'
    }.each do |msg_type, msg_name|
      it "maps response msg_type #{msg_type} to #{msg_name}" do
        subscriber.on_response(build_kerberos_message(msg_type: msg_type))

        expect(@output).to include("# Kerberos Response: #{msg_name}")
      end
    end
  end

  describe 'value serialization' do
    context 'when serializing a binary string' do
      let(:binary_preview) { '00' * 32 }
      let(:request) do
        build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::AS_REQ,
          fields: { ticket: ("\x00".b * 40) }
        )
      end

      it 'logs a bounded binary preview instead of raw data' do
        subscriber.on_request(request)

        expect(@output.any? { |line| line.include?("[binary 40 bytes: #{binary_preview}...]") }).to be(true)
      end
    end

    context 'when serializing structured values' do
      let(:error_code) do
        double(
          'error_code',
          name: 'KRB_AP_ERR_MODIFIED',
          value: 41,
          description: 'Message stream modified'
        )
      end

      let(:request_time) { Time.utc(2026, 3, 7, 12, 0, 0) }
      let(:request) do
        build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::KRB_ERROR,
          fields: {
            stime: request_time,
            tags: %i[ap error],
            metadata: { source: :kdc },
            error_code: error_code
          }
        )
      end

      it 'serializes time, symbols, hashes, arrays and error-code objects' do
        subscriber.on_request(request)

        expect(@output).to include('  "stime": "2026-03-07T12:00:00Z",')
        expect(@output).to include('    "ap",')
        expect(@output).to include('    "error"')
        expect(@output).to include('    "source": "kdc"')
        expect(@output).to include('    "name": "KRB_AP_ERR_MODIFIED",')
        expect(@output).to include('    "value": 41,')
        expect(@output).to include('    "description": "Message stream modified"')
      end
    end
  end

  def build_kerberos_message(msg_type:, fields: {})
    payload = {
      pvno: 5,
      msg_type: msg_type,
      crealm: 'EXAMPLE.LOCAL'
    }.merge(fields)

    double(
      'kerberos_message',
      attributes: payload.keys,
      **payload
    )
  end
end
