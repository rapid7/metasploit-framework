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
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REQ',
          color_prefix: '%bld%red',
          body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REQ, msg_name: 'AS-REQ')
        )
      end

      it 'prints a colored request header and readable text payload' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when the readable text presenter raises an error' do
      let(:expected_output) do
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REQ',
          color_prefix: '%bld%red',
          body: 'Kerberos trace rendering error: RuntimeError: boom'
        )
      end

      before do
        allow(subscriber).to receive(:readable_text_presenter).and_raise(RuntimeError, 'boom')
      end

      it 'prints an error placeholder without interrupting the flow' do
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
        expected_trace_output(
          direction: 'Request',
          message_name: 'UNKNOWN (999)',
          color_prefix: '%bld%red',
          body: expected_basic_body(msg_type: 999, msg_name: 'UNKNOWN')
        )
      end

      it 'prints UNKNOWN with the numeric msg_type' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when request object does not expose attributes' do
      let(:request_message) { 'raw-payload' }
      let(:expected_output) do
        expected_trace_output(
          direction: 'Request',
          message_name: 'UNKNOWN',
          color_prefix: '%bld%red',
          body: 'raw-payload'
        )
      end

      it 'falls back to to_s formatting' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    {
      'red/blu' => '%bld%red',
      'yel/' => '%bld%yel',
      '/grn' => '',
      'blu' => '%bld%blu',
      '/' => '',
      '   ' => '%bld%red'
    }.each do |configured_colors, expected_prefix|
      context "when KerberosTicketTraceColors is set to #{configured_colors.inspect}" do
        let(:trace_colors) { configured_colors }
        let(:expected_output) do
          expected_trace_output(
            direction: 'Request',
            message_name: 'AS-REQ',
            color_prefix: expected_prefix,
            body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REQ, msg_name: 'AS-REQ')
          )
        end

        it 'uses the expected request color prefix' do
          log_request

          expect(output_text).to eq(expected_output)
        end
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
          expected_trace_output(
            direction: 'Request',
            message_name: msg_name,
            color_prefix: '%bld%red',
            body: expected_basic_body(msg_type: msg_type, msg_name: msg_name)
          )
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
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REQ',
          color_prefix: '%bld%red',
          body: <<~EOF.rstrip
            Protocol Version: 5
            Message Type: #{Rex::Proto::Kerberos::Model::AS_REQ} (AS-REQ)
            Client Realm: EXAMPLE.LOCAL
            Ticket: [binary 40 bytes: #{binary_hex}]
          EOF
        )
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
        expected_trace_output(
          direction: 'Request',
          message_name: 'KRB-ERROR',
          color_prefix: '%bld%red',
          body: <<~EOF.rstrip
            Protocol Version: 5
            Message Type: #{Rex::Proto::Kerberos::Model::KRB_ERROR} (KRB-ERROR)
            Client Realm: EXAMPLE.LOCAL
            Server Time: 2026-03-07T12:00:00Z
            Tags:
              - ap
              - error
            Metadata:
              Source: kdc
            Error Code:
              Name: KRB_AP_ERR_MODIFIED
              Value: 41
              Description: Message stream modified
            KDC Options:
              Value: #{kdc_options.to_i}
              Flags:
                - FORWARDABLE
                - RENEWABLE
            Etype Set:
              - 18
              - 17
          EOF
        )
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
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REP',
          color_prefix: '%bld%red',
          body: <<~EOF.rstrip
            Protocol Version: 5
            Message Type: #{Rex::Proto::Kerberos::Model::AS_REP} (AS-REP)
            Client Realm: EXAMPLE.LOCAL
            Ticket:
              Ticket Version Number: 5
              Realm: EXAMPLE.LOCAL
              Server Name:
                Name Type: #{Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST} (NT_SRV_INST)
                Name String:
                  - krbtgt
                  - EXAMPLE.LOCAL
              Encrypted Part:
                Encryption Type: #{Rex::Proto::Kerberos::Crypto::Encryption::AES256} (AES256)
                Key Version Number: 2
                Cipher: [binary 3 bytes: 010203]
          EOF
        )
      end

      it 'recursively serializes nested model attributes' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when serializing PA-DATA types and etype arrays' do
      let(:request_message) do
        build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::AS_REQ,
          fields: {
            pa_data: [
              Rex::Proto::Kerberos::Model::PreAuthDataEntry.new(
                type: Rex::Proto::Kerberos::Model::PreAuthType::PA_PAC_REQUEST,
                value: "\x30\x05\xA0\x03\x01\x01\xFF".b
              )
            ],
            req_body: Rex::Proto::Kerberos::Model::KdcRequestBody.new(
              etype: [
                Rex::Proto::Kerberos::Crypto::Encryption::AES256,
                Rex::Proto::Kerberos::Crypto::Encryption::AES128,
                Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC
              ]
            )
          }
        )
      end
      let(:expected_output) do
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REQ',
          color_prefix: '%bld%red',
          body: <<~EOF.rstrip
            Protocol Version: 5
            Message Type: #{Rex::Proto::Kerberos::Model::AS_REQ} (AS-REQ)
            Client Realm: EXAMPLE.LOCAL
            Pre-Authentication Data:
              Entry[0]:
                Type: #{Rex::Proto::Kerberos::Model::PreAuthType::PA_PAC_REQUEST} (PA_PAC_REQUEST)
                Value: [binary 7 bytes: 3005a0030101ff]
            Request Body:
              Encryption Type:
                - #{Rex::Proto::Kerberos::Crypto::Encryption::AES256} (AES256)
                - #{Rex::Proto::Kerberos::Crypto::Encryption::AES128} (AES128)
                - #{Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC} (RC4_HMAC)
          EOF
        )
      end

      it 'renders key enum values in a readable value+name format' do
        log_request

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when serializing unknown enum values in mapped fields' do
      let(:request_message) do
        build_kerberos_message(
          msg_type: 12_345,
          fields: {
            req_body: Rex::Proto::Kerberos::Model::KdcRequestBody.new(
              cname: Rex::Proto::Kerberos::Model::PrincipalName.new(
                name_type: 54_321,
                name_string: ['user']
              )
            )
          }
        )
      end
      let(:expected_output) do
        expected_trace_output(
          direction: 'Request',
          message_name: 'UNKNOWN (12345)',
          color_prefix: '%bld%red',
          body: <<~EOF.rstrip
            Protocol Version: 5
            Message Type: 12345 (UNKNOWN)
            Client Realm: EXAMPLE.LOCAL
            Request Body:
              Client Name:
                Name Type: 54321 (UNKNOWN)
                Name String:
                  - user
          EOF
        )
      end

      it 'uses UNKNOWN labels for unmapped enum values' do
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
        expected_trace_output(
          direction: 'Response',
          message_name: 'AS-REP',
          color_prefix: '%bld%blu',
          body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REP, msg_name: 'AS-REP')
        )
      end

      it 'prints a colored response header and readable text payload' do
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
        expected_trace_output(
          direction: 'Response',
          message_name: 'UNKNOWN (31337)',
          color_prefix: '%bld%blu',
          body: expected_basic_body(msg_type: 31_337, msg_name: 'UNKNOWN')
        )
      end

      it 'prints UNKNOWN with the numeric msg_type' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    context 'when response object does not expose attributes' do
      let(:response_message) { :raw_payload }
      let(:expected_output) do
        expected_trace_output(
          direction: 'Response',
          message_name: 'UNKNOWN',
          color_prefix: '%bld%blu',
          body: 'raw_payload'
        )
      end

      it 'falls back to to_s formatting' do
        log_response

        expect(output_text).to eq(expected_output)
      end
    end

    {
      'red/blu' => '%bld%blu',
      'yel/' => '',
      '/grn' => '%bld%grn',
      'blu' => '',
      '/' => ''
    }.each do |configured_colors, expected_prefix|
      context "when KerberosTicketTraceColors is set to #{configured_colors.inspect}" do
        let(:trace_colors) { configured_colors }
        let(:expected_output) do
          expected_trace_output(
            direction: 'Response',
            message_name: 'AS-REP',
            color_prefix: expected_prefix,
            body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REP, msg_name: 'AS-REP')
          )
        end

        it 'uses the expected response color prefix' do
          log_response

          expect(output_text).to eq(expected_output)
        end
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
          expected_trace_output(
            direction: 'Response',
            message_name: msg_name,
            color_prefix: '%bld%blu',
            body: expected_basic_body(msg_type: msg_type, msg_name: msg_name)
          )
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

  def expected_trace_output(direction:, message_name:, color_prefix:, body:)
    [
      '####################',
      "# Kerberos #{direction}: #{message_name}",
      '####################',
      "%clr#{color_prefix}#{body}%clr"
    ].join("\n")
  end

  def expected_basic_body(msg_type:, msg_name:)
    <<~EOF.rstrip
      Protocol Version: 5
      Message Type: #{msg_type} (#{msg_name})
      Client Realm: EXAMPLE.LOCAL
    EOF
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
