# -*- coding: binary -*-

require 'set'
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::KerberosLoggerSubscriber do
  include_context 'Msf::UIDriver'

  subject(:subscriber) { described_class.new(logger: logger) }

  let(:trace_enabled) { true }
  let(:trace_colors) { nil }
  let(:mock_datastore) do
    {
      'KerberosTicketTrace' => trace_enabled,
      'KerberosTicketTraceColors' => trace_colors
    }
  end
  let(:logger) { instance_double(Msf::Exploit, datastore: mock_datastore) }
  let(:output_text) { @output&.join("\n") }

  describe '#initialize' do
    subject(:build_subscriber) { described_class.new(logger: logger) }

    context 'when logger responds to print_line and datastore' do
      let(:logger) { double('logger', print_line: nil, datastore: {}) }

      it 'initializes successfully' do
        expect { build_subscriber }.not_to raise_error
      end
    end

    context 'when logger does not respond to print_line' do
      let(:logger) { double('logger', datastore: {}) }

      it 'raises an incompatible logger error' do
        expect { build_subscriber }.to raise_error(RuntimeError, 'Incompatible logger')
      end
    end

    context 'when logger does not respond to datastore' do
      let(:logger) { double('logger', print_line: nil) }

      it 'raises an incompatible logger error' do
        expect { build_subscriber }.to raise_error(RuntimeError, 'Incompatible logger')
      end
    end
  end

  describe '#on_request' do
    subject(:log_request) { subscriber.on_request(request_message) }

    let(:request_message) { build_kerberos_message(msg_type: Rex::Proto::Kerberos::Model::AS_REQ) }

    before do
      capture_logging(logger)
    end

    context 'when KerberosTicketTrace is enabled with default colors' do
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr%bld%red{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'prints a colored request header and JSON payload' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTrace is false' do
      let(:trace_enabled) { false }

      it 'does not print anything' do
        log_request

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is nil' do
      let(:trace_enabled) { nil }

      it 'does not print anything' do
        log_request

        expect(output_text).to be_nil
      end
    end

    context 'when request msg_type is unknown' do
      let(:request_message) { build_kerberos_message(msg_type: 999) }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: UNKNOWN (999)
          ####################
          %clr%bld%red{
            "pvno": 5,
            "msg_type": 999,
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'prints UNKNOWN with the numeric msg_type' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when request object does not expose attributes' do
      let(:request_message) { 'raw-payload' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: UNKNOWN
          ####################
          %clr%bld%redraw-payload%clr
        EOF
      end

      it 'falls back to to_s formatting' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to red/blu' do
      let(:trace_colors) { 'red/blu' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr%bld%red{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'uses the configured request color' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to yel/' do
      let(:trace_colors) { 'yel/' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr%bld%yel{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'uses the configured request color with a blank response color' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to /grn' do
      let(:trace_colors) { '/grn' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'uses no request color when the request side is blank' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to blu' do
      let(:trace_colors) { 'blu' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr%bld%blu{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'treats a single color as request-only' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to /' do
      let(:trace_colors) { '/' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'disables both request and response color prefixes' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is blank' do
      let(:trace_colors) { '   ' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr%bld%red{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'falls back to default red/blu colors' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    {
      Rex::Proto::Kerberos::Model::AS_REP => 'AS-REP',
      Rex::Proto::Kerberos::Model::TGS_REQ => 'TGS-REQ',
      Rex::Proto::Kerberos::Model::TGS_REP => 'TGS-REP',
      Rex::Proto::Kerberos::Model::AP_REQ => 'AP-REQ',
      Rex::Proto::Kerberos::Model::AP_REP => 'AP-REP',
      Rex::Proto::Kerberos::Model::KRB_ERROR => 'KRB-ERROR'
    }.each do |msg_type, msg_name|
      context "when request msg_type is #{msg_name}" do
        let(:request_message) { build_kerberos_message(msg_type: msg_type) }
        let(:expected_output) do
          <<~EOF.rstrip
            ####################
            # Kerberos Request: #{msg_name}
            ####################
            %clr%bld%red{
              "pvno": 5,
              "msg_type": #{msg_type},
              "crealm": "EXAMPLE.LOCAL"
            }%clr
          EOF
        end

        it 'maps message type to the expected label' do
          log_request

          expect(output_text).to eq(expected_output)
        end
      end
    end

    context 'when serializing a binary string field' do
      let(:binary_hex) { '00' * 40 }
      let(:request_message) do
        build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::AS_REQ,
          fields: { ticket: ("\x00".b * 40) }
        )
      end
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REQ
          ####################
          %clr%bld%red{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REQ},
            "crealm": "EXAMPLE.LOCAL",
            "ticket": "[binary 40 bytes: #{binary_hex}]"
          }%clr
        EOF
      end

      it 'prints binary data as tagged hex bytes' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when serializing structured scalar values' do
      let(:error_code) do
        double(
          'error_code',
          name: 'KRB_AP_ERR_MODIFIED',
          value: 41,
          description: 'Message stream modified'
        )
      end
      let(:request_time) { Time.utc(2026, 3, 7, 12, 0, 0) }
      let(:kdc_options) do
        Rex::Proto::Kerberos::Model::KdcOptionFlags.from_flags([
          Rex::Proto::Kerberos::Model::KdcOptionFlags::FORWARDABLE,
          Rex::Proto::Kerberos::Model::KdcOptionFlags::RENEWABLE
        ])
      end
      let(:request_message) do
        build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::KRB_ERROR,
          fields: {
            stime: request_time,
            tags: %i[ap error],
            metadata: { source: :kdc },
            error_code: error_code,
            options: kdc_options,
            etype_set: Set.new([18, 17])
          }
        )
      end
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: KRB-ERROR
          ####################
          %clr%bld%red{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::KRB_ERROR},
            "crealm": "EXAMPLE.LOCAL",
            "stime": "2026-03-07T12:00:00Z",
            "tags": [
              "ap",
              "error"
            ],
            "metadata": {
              "source": "kdc"
            },
            "error_code": {
              "name": "KRB_AP_ERR_MODIFIED",
              "value": 41,
              "description": "Message stream modified"
            },
            "options": {
              "value": #{kdc_options.to_i},
              "flags": [
                "FORWARDABLE",
                "RENEWABLE"
              ]
            },
            "etype_set": [
              18,
              17
            ]
          }%clr
        EOF
      end

      it 'normalizes time, symbols, flags, sets and error code objects' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when serializing nested Kerberos model objects' do
      let(:ticket) do
        Rex::Proto::Kerberos::Model::Ticket.new(
          tkt_vno: 5,
          realm: 'EXAMPLE.LOCAL',
          sname: Rex::Proto::Kerberos::Model::PrincipalName.new(
            name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
            name_string: %w[krbtgt EXAMPLE.LOCAL]
          ),
          enc_part: Rex::Proto::Kerberos::Model::EncryptedData.new(
            etype: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
            kvno: 2,
            cipher: "\x01\x02\x03".b
          )
        )
      end
      let(:request_message) do
        build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::AS_REP,
          fields: { ticket: ticket }
        )
      end
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Request: AS-REP
          ####################
          %clr%bld%red{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REP},
            "crealm": "EXAMPLE.LOCAL",
            "ticket": {
              "tkt_vno": 5,
              "realm": "EXAMPLE.LOCAL",
              "sname": {
                "name_type": #{Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST},
                "name_string": [
                  "krbtgt",
                  "EXAMPLE.LOCAL"
                ]
              },
              "enc_part": {
                "etype": #{Rex::Proto::Kerberos::Crypto::Encryption::AES256},
                "kvno": 2,
                "cipher": "[binary 3 bytes: 010203]"
              }
            }
          }%clr
        EOF
      end

      it 'recursively serializes nested model attributes' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end
  end

  describe '#on_response' do
    subject(:log_response) { subscriber.on_response(response_message) }

    let(:response_message) { build_kerberos_message(msg_type: Rex::Proto::Kerberos::Model::AS_REP) }

    before do
      capture_logging(logger)
    end

    context 'when KerberosTicketTrace is enabled with default colors' do
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: AS-REP
          ####################
          %clr%bld%blu{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REP},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'prints a colored response header and JSON payload' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when response is nil' do
      let(:response_message) { nil }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: UNKNOWN
          ####################
          No response received
        EOF
      end

      it 'prints a no-response message' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTrace is false' do
      let(:trace_enabled) { false }

      it 'does not print anything' do
        log_response

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is nil' do
      let(:trace_enabled) { nil }

      it 'does not print anything' do
        log_response

        expect(output_text).to be_nil
      end
    end

    context 'when response msg_type is unknown' do
      let(:response_message) { build_kerberos_message(msg_type: 31_337) }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: UNKNOWN (31337)
          ####################
          %clr%bld%blu{
            "pvno": 5,
            "msg_type": 31337,
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'prints UNKNOWN with the numeric msg_type' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when response object does not expose attributes' do
      let(:response_message) { :raw_payload }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: UNKNOWN
          ####################
          %clr%bld%bluraw_payload%clr
        EOF
      end

      it 'falls back to to_s formatting' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to red/blu' do
      let(:trace_colors) { 'red/blu' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: AS-REP
          ####################
          %clr%bld%blu{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REP},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'uses the configured response color' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to yel/' do
      let(:trace_colors) { 'yel/' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: AS-REP
          ####################
          %clr{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REP},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'uses no response color when the response side is blank' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to /grn' do
      let(:trace_colors) { '/grn' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: AS-REP
          ####################
          %clr%bld%grn{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REP},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'uses the configured response color' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to blu' do
      let(:trace_colors) { 'blu' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: AS-REP
          ####################
          %clr{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REP},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'treats a single color as request-only' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when KerberosTicketTraceColors is set to /' do
      let(:trace_colors) { '/' }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Response: AS-REP
          ####################
          %clr{
            "pvno": 5,
            "msg_type": #{Rex::Proto::Kerberos::Model::AS_REP},
            "crealm": "EXAMPLE.LOCAL"
          }%clr
        EOF
      end

      it 'disables both request and response color prefixes' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    {
      Rex::Proto::Kerberos::Model::AS_REQ => 'AS-REQ',
      Rex::Proto::Kerberos::Model::TGS_REQ => 'TGS-REQ',
      Rex::Proto::Kerberos::Model::TGS_REP => 'TGS-REP',
      Rex::Proto::Kerberos::Model::AP_REQ => 'AP-REQ',
      Rex::Proto::Kerberos::Model::AP_REP => 'AP-REP',
      Rex::Proto::Kerberos::Model::KRB_ERROR => 'KRB-ERROR'
    }.each do |msg_type, msg_name|
      context "when response msg_type is #{msg_name}" do
        let(:response_message) { build_kerberos_message(msg_type: msg_type) }
        let(:expected_output) do
          <<~EOF.rstrip
            ####################
            # Kerberos Response: #{msg_name}
            ####################
            %clr%bld%blu{
              "pvno": 5,
              "msg_type": #{msg_type},
              "crealm": "EXAMPLE.LOCAL"
            }%clr
          EOF
        end

        it 'maps message type to the expected label' do
          log_response

          expect(output_text).to eq(expected_output)
        end
      end
    end
  end

  describe '#on_credential' do
    subject(:log_credential) { subscriber.on_credential(credential_to_log, source: source) }

    let(:credential) { double('credential') }
    let(:credential_to_log) { credential }
    let(:source) { 'TGS' }
    let(:presented_credential) do
      <<~EOF.rstrip
        Server: krbtgt/EXAMPLE.LOCAL@EXAMPLE.LOCAL
        Client: Administrator@EXAMPLE.LOCAL
        Ticket etype: 18 (AES256)
        Key: deadbeef
      EOF
    end
    let(:presenter) do
      instance_double(
        Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter,
        present_cred: presented_credential
      )
    end

    before do
      capture_logging(logger)
      allow(Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter).to receive(:new).with(nil).and_return(presenter)
    end

    context 'when trace is enabled and credential is present' do
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Credential: TGS
          ####################
          Creds: 1
            Credential[0]:
              Server: krbtgt/EXAMPLE.LOCAL@EXAMPLE.LOCAL
              Client: Administrator@EXAMPLE.LOCAL
              Ticket etype: 18 (AES256)
              Key: deadbeef
        EOF
      end

      it 'prints presenter output under the credential header' do
        log_credential

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when source is nil' do
      let(:source) { nil }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Credential
          ####################
          Creds: 1
            Credential[0]:
              Server: krbtgt/EXAMPLE.LOCAL@EXAMPLE.LOCAL
              Client: Administrator@EXAMPLE.LOCAL
              Ticket etype: 18 (AES256)
              Key: deadbeef
        EOF
      end

      it 'omits the source suffix from the header' do
        log_credential

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when credential is nil' do
      let(:credential_to_log) { nil }

      it 'does not print anything' do
        log_credential

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is false' do
      let(:trace_enabled) { false }

      it 'does not print anything' do
        log_credential

        expect(output_text).to be_nil
      end
    end

    context 'when presenter raises an error' do
      let(:presenter) { instance_double(Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter) }
      let(:expected_output) do
        <<~EOF.rstrip
          ####################
          # Kerberos Credential: TGS
          ####################
          Credential presenter error: RuntimeError: boom
        EOF
      end

      before do
        allow(presenter).to receive(:present_cred).with(credential).and_raise(RuntimeError, 'boom')
      end

      it 'prints the presenter error message' do
        log_credential

        expect(output_text).to eq(expected_output)
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
