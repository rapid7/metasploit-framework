# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::KerberosLoggerSubscriber do
  include_context 'Msf::UIDriver'

  let(:mock_module) { instance_double(Msf::Exploit, datastore: mock_datastore) }

  subject do
    capture_logging(mock_module)
    described_class.new(logger: mock_module)
  end

  let(:sample_request) do
    Rex::Proto::Kerberos::Model::KdcRequest.decode(
      "\x6a\x82\x01\x08\x30\x82\x01\x04\xa1\x03\x02\x01" \
      "\x05\xa2\x03\x02\x01\x0a\xa3\x5f\x30\x5d\x30\x48\xa1\x03\x02\x01" \
      "\x02\xa2\x41\x04\x3f\x30\x3d\xa0\x03\x02\x01\x17\xa2\x36\x04\x34" \
      "\x60\xae\x53\xa5\x0b\x56\x2e\x46\x61\xd9\xd6\x89\x98\xfc\x79\x9d" \
      "\x45\x73\x7d\x0d\x8a\x78\x84\x4d\xd7\x7c\xc6\x50\x08\x8d\xab\x22" \
      "\x79\xc3\x8d\xd3\xaf\x9f\x5e\xb7\xb8\x9b\x57\xc5\xc9\xc5\xea\x90" \
      "\x89\xc3\x63\x58\x30\x11\xa1\x04\x02\x02\x00\x80\xa2\x09\x04\x07" \
      "\x30\x05\xa0\x03\x01\x01\x00\xa4\x81\x96\x30\x81\x93\xa0\x07\x03" \
      "\x05\x00\x50\x80\x00\x00\xa1\x11\x30\x0f\xa0\x03\x02\x01\x01\xa1" \
      "\x08\x30\x06\x1b\x04\x6a\x75\x61\x6e\xa2\x0c\x1b\x0a\x44\x45\x4d" \
      "\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x1f\x30\x1d\xa0\x03\x02\x01\x01" \
      "\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0a\x44\x45" \
      "\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa4\x11\x18\x0f\x31\x39\x37\x30" \
      "\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa5\x11\x18\x0f\x31" \
      "\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa6\x11" \
      "\x18\x0f\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30" \
      "\x5a\xa7\x06\x02\x04\x18\xf4\x10\x2c\xa8\x05\x30\x03\x02\x01\x17"
    )
  end

  let(:sample_error_response) do
    Rex::Proto::Kerberos::Client.new.send(
      :decode_kerb_response,
      "\x7e\x81\x8d\x30\x81\x8a\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e" \
      "\xa4\x11\x18\x0f\x32\x30\x32\x32\x30\x35\x32\x36\x31\x35\x34\x33" \
      "\x32\x38\x5a\xa5\x05\x02\x03\x0e\x51\x88\xa6\x03\x02\x01\x18\xa9" \
      "\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xaa\x1f\x30" \
      "\x1d\xa0\x03\x02\x01\x01\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74" \
      "\x67\x74\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xac\x30" \
      "\x04\x2e\x30\x2c\x30\x16\xa1\x03\x02\x01\x0b\xa2\x0f\x04\x0d\x30" \
      "\x0b\x30\x09\xa0\x03\x02\x01\x17\xa1\x02\x04\x00\x30\x12\xa1\x03" \
      "\x02\x01\x13\xa2\x0b\x04\x09\x30\x07\x30\x05\xa0\x03\x02\x01\x17"
    )
  end

  describe '#on_request' do
    let(:context) { { peer: '127.0.0.1:88' } }

    context 'when KerberosTicketTrace is enabled' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceLevel' => 'summary'
        }
      end

      it 'logs a Kerberos request summary' do
        subject.on_request(sample_request, context: context)

        expect(@output).to include('####################')
        expect(@output).to include('# Kerberos Request:')
        expect(@output).to include('peer=127.0.0.1:88 msg=AS-REQ realm=DEMO.LOCAL cname=juan sname=krbtgt/DEMO.LOCAL')
      end
    end

    context 'when raw tracing is enabled' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => true,
          'KerberosTicketTraceLevel' => 'raw'
        }
      end

      it 'logs a redacted raw preview' do
        subject.on_request(sample_request, raw: ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"), context: context)

        expect(@output).to include('pvno=5 msg_type=10 pa_data_count=2 etypes=23')
        expect(@output).to include('raw_length=10')
        expect(@output).to include('raw_preview=01 02 03 04 05 06 07 08 09 0a')
      end
    end

    context 'when KerberosTicketTrace is disabled' do
      let(:mock_datastore) do
        {
          'KerberosTicketTrace' => false
        }
      end

      it 'does not log the request' do
        subject.on_request(sample_request, context: context)

        expect(@output).to eq(nil)
      end
    end
  end

  describe '#on_response' do
    let(:context) { { peer: '127.0.0.1:88' } }
    let(:mock_datastore) do
      {
        'KerberosTicketTrace' => true,
        'KerberosTicketTraceLevel' => 'raw'
      }
    end

    it 'logs a Kerberos response summary and message details' do
      subject.on_response(sample_error_response, context: context)

      expect(@output).to include('peer=127.0.0.1:88 msg=KRB-ERROR realm=DEMO.LOCAL sname=krbtgt/DEMO.LOCAL error=KDC_ERR_PREAUTH_FAILED(24)')
      expect(@output).to include('pvno=5 msg_type=30 server_time=2022-05-26T15:43:28Z e_data_present=true')
    end
  end
end
