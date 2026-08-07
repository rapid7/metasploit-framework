# -*- coding: binary -*-
# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

require 'spec_helper'
require 'set'

RSpec.describe Rex::Proto::Kerberos::KerberosLoggerSubscriber do
  include_context 'Msf::UIDriver'

  # -- Shared doubles ---------------------------------------------------------

  subject(:subscriber) { described_class.new(logger: logger) }

  let(:trace_mode) { 'full' }

  let(:trace_colors) { nil }

  let(:mock_datastore) do
    {
      'KerberosTicketTrace' => trace_mode,
      'KerberosTicketTraceColors' => trace_colors
    }
  end

  let(:logger) { instance_double(Msf::Exploit, datastore: mock_datastore) }

  let(:output_text) { @output&.join("\n") }

  let(:request_message) { build_kerberos_message(msg_type: Rex::Proto::Kerberos::Model::AS_REQ) }

  let(:response_message) { build_kerberos_message(msg_type: Rex::Proto::Kerberos::Model::AS_REP) }

  # -- #initialize ------------------------------------------------------------

  describe '#initialize' do
    it 'initializes when the logger supports print_line and datastore' do
      logger = double('logger', print_line: nil, datastore: {})

      expect { described_class.new(logger: logger) }.not_to raise_error
    end

    it 'raises when the logger does not support print_line' do
      logger = double('logger', datastore: {})

      expect { described_class.new(logger: logger) }.to raise_error(RuntimeError, 'Incompatible logger')
    end

    it 'raises when the logger does not support datastore' do
      logger = double('logger', print_line: nil)

      expect { described_class.new(logger: logger) }.to raise_error(RuntimeError, 'Incompatible logger')
    end
  end

  # -- #on_request ------------------------------------------------------------

  describe '#on_request' do
    subject(:log_request) { subscriber.on_request(request_message) }

    before do
      capture_logging(logger)
    end

    it 'prints a colored request header and readable text payload' do
      log_request

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REQ',
          color_prefix: '%bld%red',
          body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REQ, msg_name: 'AS-REQ')
        )
      )
    end

    it 'prints an error placeholder when the readable text presenter raises' do
      allow(subscriber).to receive(:readable_text_presenter).and_raise(RuntimeError, 'boom')

      log_request

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REQ',
          color_prefix: '%bld%red',
          body: 'Kerberos trace rendering error: RuntimeError: boom'
        )
      )
    end

    it 'prints UNKNOWN with the numeric request msg_type' do
      subscriber.on_request(build_kerberos_message(msg_type: 999))

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Request',
          message_name: 'UNKNOWN (999)',
          color_prefix: '%bld%red',
          body: expected_basic_body(msg_type: 999, msg_name: 'UNKNOWN')
        )
      )
    end

    it 'falls back to to_s formatting when the request does not expose attributes' do
      subscriber.on_request('raw-payload')

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Request',
          message_name: 'UNKNOWN',
          color_prefix: '%bld%red',
          body: 'raw-payload'
        )
      )
    end

    it 'renders nil request payloads as null' do
      subscriber.on_request(nil)

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Request',
          message_name: 'UNKNOWN',
          color_prefix: '%bld%red',
          body: 'null'
        )
      )
    end

    it 'prints binary string fields as tagged hex bytes' do
      binary_hex = '00' * 40
      request = build_kerberos_message(
        msg_type: Rex::Proto::Kerberos::Model::AS_REQ,
        fields: { ticket: ("\x00".b * 40) }
      )

      subscriber.on_request(request)

      expect(output_text).to eq(
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
      )
    end

    context 'when KerberosTicketTrace is metadata' do
      let(:trace_mode) { 'metadata' }

      it 'prints a concise payload without expanding binary field contents' do
        request = build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::AS_REQ,
          fields: {
            ticket: ("\x00".b * 40),
            req_body: Rex::Proto::Kerberos::Model::KdcRequestBody.new(
              etype: [
                Rex::Proto::Kerberos::Crypto::Encryption::AES256,
                Rex::Proto::Kerberos::Crypto::Encryption::AES128
              ]
            )
          }
        )

        subscriber.on_request(request)

        expect(output_text).to eq(
          expected_trace_output(
            direction: 'Request',
            message_name: 'AS-REQ',
            color_prefix: '%bld%red',
            body: <<~EOF.rstrip
              Protocol Version: 5
              Message Type: #{Rex::Proto::Kerberos::Model::AS_REQ} (AS-REQ)
              Client Realm: EXAMPLE.LOCAL
              Ticket: [binary 40 bytes]
              Request Body:
                Encryption Type:
                  - #{Rex::Proto::Kerberos::Crypto::Encryption::AES256} (AES256)
                  - #{Rex::Proto::Kerberos::Crypto::Encryption::AES128} (AES128)
            EOF
          )
        )
      end
    end

    it 'normalizes time, symbols, flags, sets and error code objects' do
      error_code = double(
        'error_code',
        name: 'KRB_AP_ERR_MODIFIED',
        value: 41,
        description: 'Message stream modified'
      )
      request_time = Time.utc(2026, 3, 7, 12, 0, 0)
      kdc_options = Rex::Proto::Kerberos::Model::KdcOptionFlags.from_flags([
        Rex::Proto::Kerberos::Model::KdcOptionFlags::FORWARDABLE,
        Rex::Proto::Kerberos::Model::KdcOptionFlags::RENEWABLE
      ])
      request = build_kerberos_message(
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

      subscriber.on_request(request)

      expect(output_text).to eq(
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
            Options:
              Value: #{kdc_options.to_i}
              Flags:
                - FORWARDABLE
                - RENEWABLE
            Etype Set:
              - 18
              - 17
          EOF
        )
      )
    end

    it 'renders AP-REQ options as AP Options' do
      request = Rex::Proto::Kerberos::Model::ApReq.new(
        pvno: 5,
        msg_type: Rex::Proto::Kerberos::Model::AP_REQ,
        options: 0
      )

      subscriber.on_request(request)

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Request',
          message_name: 'AP-REQ',
          color_prefix: '%bld%red',
          body: <<~EOF.rstrip
            Protocol Version: 5
            Message Type: #{Rex::Proto::Kerberos::Model::AP_REQ} (AP-REQ)
            AP Options: 0
          EOF
        )
      )
    end

    it 'renders KDC request body options as KDC Options' do
      kdc_options = Rex::Proto::Kerberos::Model::KdcOptionFlags.from_flags([
        Rex::Proto::Kerberos::Model::KdcOptionFlags::FORWARDABLE
      ])
      request = Rex::Proto::Kerberos::Model::KdcRequest.new(
        pvno: 5,
        msg_type: Rex::Proto::Kerberos::Model::AS_REQ,
        req_body: Rex::Proto::Kerberos::Model::KdcRequestBody.new(
          options: kdc_options
        )
      )

      subscriber.on_request(request)

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Request',
          message_name: 'AS-REQ',
          color_prefix: '%bld%red',
          body: <<~EOF.rstrip
            Protocol Version: 5
            Message Type: #{Rex::Proto::Kerberos::Model::AS_REQ} (AS-REQ)
            Request Body:
              KDC Options:
                Value: #{kdc_options.to_i}
                Flags:
                  - FORWARDABLE
          EOF
        )
      )
    end

    it 'recursively serializes nested Kerberos model attributes' do
      ticket = Rex::Proto::Kerberos::Model::Ticket.new(
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
      request = build_kerberos_message(
        msg_type: Rex::Proto::Kerberos::Model::AS_REP,
        fields: { ticket: ticket }
      )

      subscriber.on_request(request)

      expect(output_text).to eq(
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
      )
    end

    it 'renders key enum values in a readable value+name format' do
      request = build_kerberos_message(
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

      subscriber.on_request(request)

      expect(output_text).to eq(
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
      )
    end

    it 'uses UNKNOWN labels for unmapped enum values' do
      request = build_kerberos_message(
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

      subscriber.on_request(request)

      expect(output_text).to eq(
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
      )
    end

    context 'when KerberosTicketTrace is off' do
      let(:trace_mode) { 'off' }

      it 'does not print anything' do
        log_request

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is false' do
      let(:trace_mode) { false }

      it 'does not print anything' do
        log_request

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is nil' do
      let(:trace_mode) { nil }

      it 'does not print anything' do
        log_request

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is ticket' do
      let(:trace_mode) { 'ticket' }

      it 'does not print request messages' do
        log_request

        expect(output_text).to be_nil
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

        it 'uses the expected request color prefix' do
          log_request

          expect(output_text).to eq(
            expected_trace_output(
              direction: 'Request',
              message_name: 'AS-REQ',
              color_prefix: expected_prefix,
              body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REQ, msg_name: 'AS-REQ')
            )
          )
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

        it 'maps message type to the expected label' do
          log_request

          expect(output_text).to eq(
            expected_trace_output(
              direction: 'Request',
              message_name: msg_name,
              color_prefix: '%bld%red',
              body: expected_basic_body(msg_type: msg_type, msg_name: msg_name)
            )
          )
        end
      end
    end
  end

  # -- #on_response -----------------------------------------------------------

  describe '#on_response' do
    subject(:log_response) { subscriber.on_response(response_message) }

    before do
      capture_logging(logger)
    end

    it 'prints a colored response header and readable text payload' do
      log_response

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Response',
          message_name: 'AS-REP',
          color_prefix: '%bld%blu',
          body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REP, msg_name: 'AS-REP')
        )
      )
    end

    it 'prints a no-response message when the response is nil' do
      subscriber.on_response(nil)

      expect(output_text).to eq(
        <<~EOF.rstrip
          ####################
          # Kerberos Response: UNKNOWN
          ####################
          No response received
        EOF
      )
    end

    it 'prints UNKNOWN with the numeric response msg_type' do
      subscriber.on_response(build_kerberos_message(msg_type: 31_337))

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Response',
          message_name: 'UNKNOWN (31337)',
          color_prefix: '%bld%blu',
          body: expected_basic_body(msg_type: 31_337, msg_name: 'UNKNOWN')
        )
      )
    end

    it 'falls back to to_s formatting when the response does not expose attributes' do
      subscriber.on_response(:raw_payload)

      expect(output_text).to eq(
        expected_trace_output(
          direction: 'Response',
          message_name: 'UNKNOWN',
          color_prefix: '%bld%blu',
          body: 'raw_payload'
        )
      )
    end

    context 'when KerberosTicketTrace is metadata' do
      let(:trace_mode) { 'metadata' }

      it 'prints response metadata without expanding encrypted data contents' do
        response = build_kerberos_message(
          msg_type: Rex::Proto::Kerberos::Model::AS_REP,
          fields: {
            enc_part: Rex::Proto::Kerberos::Model::EncryptedData.new(
              etype: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
              kvno: 2,
              cipher: "\x01\x02\x03".b
            )
          }
        )

        subscriber.on_response(response)

        expect(output_text).to eq(
          expected_trace_output(
            direction: 'Response',
            message_name: 'AS-REP',
            color_prefix: '%bld%blu',
            body: <<~EOF.rstrip
              Protocol Version: 5
              Message Type: #{Rex::Proto::Kerberos::Model::AS_REP} (AS-REP)
              Client Realm: EXAMPLE.LOCAL
              Encrypted Part:
                Encryption Type: #{Rex::Proto::Kerberos::Crypto::Encryption::AES256} (AES256)
                Key Version Number: 2
                Cipher: [binary 3 bytes]
            EOF
          )
        )
      end
    end

    context 'when KerberosTicketTrace is ticket' do
      let(:trace_mode) { 'ticket' }

      it 'does not print response messages' do
        log_response

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is off' do
      let(:trace_mode) { 'off' }

      it 'does not print anything' do
        log_response

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is false' do
      let(:trace_mode) { false }

      it 'does not print anything' do
        log_response

        expect(output_text).to be_nil
      end
    end

    context 'when KerberosTicketTrace is nil' do
      let(:trace_mode) { nil }

      it 'does not print anything' do
        log_response

        expect(output_text).to be_nil
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

        it 'uses the expected response color prefix' do
          log_response

          expect(output_text).to eq(
            expected_trace_output(
              direction: 'Response',
              message_name: 'AS-REP',
              color_prefix: expected_prefix,
              body: expected_basic_body(msg_type: Rex::Proto::Kerberos::Model::AS_REP, msg_name: 'AS-REP')
            )
          )
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

        it 'maps message type to the expected label' do
          log_response

          expect(output_text).to eq(
            expected_trace_output(
              direction: 'Response',
              message_name: msg_name,
              color_prefix: '%bld%blu',
              body: expected_basic_body(msg_type: msg_type, msg_name: msg_name)
            )
          )
        end
      end
    end
  end

  # -- #on_credential ---------------------------------------------------------

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

    let(:presented_credentials) do
      <<~EOF.rstrip
        Creds: 1
          Credential[0]:
            #{presented_credential.gsub("\n", "\n    ")}
      EOF
    end

    let(:presenter) do
      instance_double(
        Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter,
        present_credentials: presented_credentials
      )
    end

    before do
      capture_logging(logger)
      allow(Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter).to receive(:new).with(nil).and_return(presenter)
    end

    it 'prints presenter output under the credential header' do
      log_credential

      expect(output_text).to eq(
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
      )
    end

    context 'when KerberosTicketTrace is ticket' do
      let(:trace_mode) { 'ticket' }

      it 'prints the full credential presenter output' do
        log_credential

        expect(output_text).to eq(
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
        )
      end
    end

    context 'when KerberosTicketTrace is metadata' do
      let(:trace_mode) { 'metadata' }
      let(:auth_time) { Time.utc(2026, 1, 1, 0, 0, 0) }
      let(:start_time) { Time.utc(2026, 1, 1, 0, 5, 0) }
      let(:end_time) { Time.utc(2026, 1, 1, 10, 0, 0) }
      let(:renew_till) { Time.utc(2026, 1, 8, 0, 0, 0) }
      let(:credential) do
        double(
          'credential',
          server: 'krbtgt/EXAMPLE.LOCAL@EXAMPLE.LOCAL',
          client: 'Administrator@EXAMPLE.LOCAL',
          keyblock: double('keyblock', enctype: Rex::Proto::Kerberos::Crypto::Encryption::AES256),
          is_skey: 0,
          ticket: double('ticket', length: 1234),
          ticket_flags: 0,
          address_count: 0,
          authdata_count: 0,
          authtime: auth_time,
          starttime: start_time,
          endtime: end_time,
          renew_till: renew_till
        )
      end
      let(:presented_credentials) do
        <<~EOF.rstrip
          Creds: 1
            Credential[0]:
              Server: krbtgt/EXAMPLE.LOCAL@EXAMPLE.LOCAL
              Client: Administrator@EXAMPLE.LOCAL
              Ticket etype: 18 (AES256)
              Subkey: false
              Ticket Length: 1234
              Ticket Flags: 0x00000000 ()
              Addresses: 0
              Authdatas: 0
              Times:
                Auth time: #{auth_time.localtime}
                Start time: #{start_time.localtime}
                End time: #{end_time.localtime}
                Renew Till: #{renew_till.localtime}
        EOF
      end

      it 'prints only high-level credential metadata' do
        log_credential

        expect(output_text).to eq(
          <<~EOF.rstrip
            ####################
            # Kerberos Credential: TGS
            ####################
            Creds: 1
              Credential[0]:
                Server: krbtgt/EXAMPLE.LOCAL@EXAMPLE.LOCAL
                Client: Administrator@EXAMPLE.LOCAL
                Ticket etype: 18 (AES256)
                Subkey: false
                Ticket Length: 1234
                Ticket Flags: 0x00000000 ()
                Addresses: 0
                Authdatas: 0
                Times:
                  Auth time: #{auth_time.localtime}
                  Start time: #{start_time.localtime}
                  End time: #{end_time.localtime}
                  Renew Till: #{renew_till.localtime}
          EOF
        )
      end
    end

    it 'omits the source suffix from the header when source is nil' do
      subscriber.on_credential(credential, source: nil)

      expect(output_text).to eq(
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
      )
    end

    it 'does not print anything when credential is nil' do
      subscriber.on_credential(nil, source: source)

      expect(output_text).to be_nil
    end

    context 'when KerberosTicketTrace is off' do
      let(:trace_mode) { 'off' }

      it 'does not print anything' do
        log_credential

        expect(output_text).to be_nil
      end
    end

    context 'when the credential presenter raises an error' do
      let(:presenter) { instance_double(Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter) }

      before do
        allow(presenter).to receive(:present_credentials).with([credential], trace_mode: trace_mode).and_raise(RuntimeError, 'boom')
      end

      it 'prints the presenter error message' do
        log_credential

        expect(output_text).to eq(
          <<~EOF.rstrip
            ####################
            # Kerberos Credential: TGS
            ####################
            Credential presenter error: RuntimeError: boom
          EOF
        )
      end
    end
  end

  # -- Service authentication trace events -----------------------------------

  describe 'service authentication trace events' do
    let(:trace_mode) { 'metadata' }
    let(:ap_req_metadata) { build_ap_req_trace_metadata }
    let(:ap_req_der) { ap_req_metadata[:ap_req].encode }
    let(:gss_token) { build_gss_kerberos_token(ap_req_der) }
    let(:spnego_token) { build_spnego_neg_token_init(gss_token) }

    before do
      capture_logging(logger)
    end

    describe '#on_ap_req' do
      it 'prints AP-REQ construction metadata without expanding binary fields' do
        subscriber.on_ap_req(ap_req_metadata)

        expect(output_text).to include('# Kerberos AP-REQ')
        expect(output_text).to include('Message Type: 14 (AP-REQ)')
        expect(output_text).to include('Mutual Authentication: requested')
        expect(output_text).to include('Service Principal: cifs/fileserver.example.local@EXAMPLE.LOCAL')
        expect(output_text).to include('Ticket etype: 18 (AES256)')
        expect(output_text).to include('Checksum Type: 32771')
        expect(output_text).to include('Checksum: [binary 24 bytes]')
        expect(output_text).not_to include('000000000000000000000000000000000000000000000000')
      end

      context 'when KerberosTicketTrace is full' do
        let(:trace_mode) { 'full' }

        it 'prints full AP-REQ and decrypted authenticator details' do
          subscriber.on_ap_req(ap_req_metadata)

          expect(output_text).to include('AP-REQ Message:')
          expect(output_text).to include('Decrypted Authenticator:')
          expect(output_text).to include('Checksum: [binary 24 bytes: 000000000000000000000000000000000000000000000000]')
          expect(output_text).to include('Session Key:')
          expect(output_text).to include('1111111111111111111111111111111111111111111111111111111111111111')
        end
      end

      context 'when KerberosTicketTrace is ticket' do
        let(:trace_mode) { 'ticket' }
        let(:credential) { double('credential') }
        let(:presenter) do
          instance_double(
            Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter,
            present_credentials: 'selected credential output'
          )
        end

        before do
          allow(Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter).to receive(:new).with(nil).and_return(presenter)
        end

        it 'prints only the selected credential' do
          subscriber.on_ap_req(ap_req_metadata.merge(credential: credential))

          expect(output_text).to eq(
            <<~EOF.rstrip
              ####################
              # Kerberos Credential: AP-REQ Selected Service Ticket
              ####################
              selected credential output
            EOF
          )
        end
      end

      context 'when KerberosTicketTrace is off' do
        let(:trace_mode) { 'off' }

        it 'does not print anything' do
          subscriber.on_ap_req(ap_req_metadata)

          expect(output_text).to be_nil
        end
      end
    end

    describe '#on_gss_token' do
      it 'prints GSS-Kerberos wrapping metadata' do
        subscriber.on_gss_token(ap_req_metadata.merge(token: gss_token, ap_req_der: ap_req_der, direction: 'outbound'))

        expect(output_text).to include('# Kerberos GSS Token')
        expect(output_text).to include('Wrapper Type: GSS-Kerberos')
        expect(output_text).to include('Mechanism OID: 1.2.840.113554.1.2.2')
        expect(output_text).to include('Inner Token Type: AP-REQ')
        expect(output_text).to include('AP-REQ Payload Matches: true')
        expect(output_text).to include("AP-REQ Payload Length: #{ap_req_der.bytesize}")
        expect(output_text).to include('Token: [binary')
      end

      context 'when KerberosTicketTrace is ticket' do
        let(:trace_mode) { 'ticket' }

        it 'does not print wrapper tokens' do
          subscriber.on_gss_token(ap_req_metadata.merge(token: gss_token, ap_req_der: ap_req_der))

          expect(output_text).to be_nil
        end
      end
    end

    describe '#on_spnego_token' do
      it 'prints SPNEGO NegTokenInit wrapping metadata' do
        subscriber.on_spnego_token(ap_req_metadata.merge(token: spnego_token, ap_req_der: ap_req_der, direction: 'outbound'))

        expect(output_text).to include('# Kerberos SPNEGO Token')
        expect(output_text).to include('Wrapper Type: SPNEGO NegTokenInit')
        expect(output_text).to include('Mechanism OID: 1.3.6.1.5.5.2')
        expect(output_text).to include('Mech Types:')
        expect(output_text).to include('1.2.840.48018.1.2.2')
        expect(output_text).to include('Optimistic Mech Token: true')
        expect(output_text).to include("Mech Token Length: #{gss_token.bytesize}")
        expect(output_text).to include('Inner AP-REQ:')
      end
    end

    describe '#on_response_token' do
      it 'prints AP-REP response token details' do
        subscriber.on_response_token(
          ap_req_metadata.merge(
            token_type: 'GSS-Kerberos',
            message: build_ap_rep_message,
            decrypted_part: build_enc_ap_rep_part,
            token: gss_token,
            mutual_authentication: 'success'
          )
        )

        expect(output_text).to include('# Kerberos Response Token')
        expect(output_text).to include('Message Type: 15 (AP-REP)')
        expect(output_text).to include('Encryption Type: 18 (AES256)')
        expect(output_text).to include('Mutual Authentication: success')
        expect(output_text).to include('Sequence Number: 1234')
        expect(output_text).to include('Subkey:')
      end

      it 'prints KRB-ERROR response token details' do
        subscriber.on_response_token(ap_req_metadata.merge(token_type: 'GSS-Kerberos', message: build_krb_error_message, token: gss_token))

        expect(output_text).to include('Message Type: 30 (KRB-ERROR)')
        expect(output_text).to include('Name: KRB_AP_ERR_MODIFIED')
        expect(output_text).to include('Value: 41')
        expect(output_text).to include('Server Principal: cifs/fileserver.example.local@EXAMPLE.LOCAL')
        expect(output_text).to include('Error Data: [binary 4 bytes]')
        expect(output_text).not_to include('Mutual Authentication: success')
      end

      it 'prints parse failure details for unparseable response tokens' do
        subscriber.on_response_token(token_type: 'GSS-Kerberos', token: 'not-asn1', carrier: 'HTTP WWW-Authenticate')

        expect(output_text).to include('Parse Failure: unable to parse response token as AP-REP/KRB-ERROR/SPNEGO')
        expect(output_text).to include('Token Length: 8')
        expect(output_text).to include('Carrier: HTTP WWW-Authenticate')
      end
    end

    describe '#on_protocol_carrier' do
      it 'prints HTTP Authorization carrier metadata and token summary' do
        subscriber.on_protocol_carrier(
          protocol: 'HTTP',
          direction: 'request',
          label: 'HTTP Authorization',
          carrier: 'Authorization header',
          header_name: 'Authorization',
          scheme: 'Negotiate',
          base64_token: Rex::Text.encode_base64(spnego_token),
          token: spnego_token,
          service_principal: 'http/www.example.local@EXAMPLE.LOCAL'
        )

        expect(output_text).to include('# Kerberos Carrier: HTTP Authorization')
        expect(output_text).to include('Header Name: Authorization')
        expect(output_text).to include('Scheme: Negotiate')
        expect(output_text).to include("Decoded Token Length: #{spnego_token.bytesize}")
        expect(output_text).to include('Token Type: SPNEGO NegTokenInit')
      end

      [
        {
          protocol: 'SMB',
          label: 'SMB Session Setup',
          carrier: 'SMB2 Session Setup security blob',
          field_name: 'security_blob'
        },
        {
          protocol: 'MSSQL',
          label: 'MSSQL SSPI',
          carrier: 'TDS7 Login SSPI security blob',
          field_name: 'sspi'
        },
        {
          protocol: 'LDAP',
          label: 'LDAP serverSaslCreds',
          carrier: 'SASL bind response serverSaslCreds',
          field_name: 'serverSaslCreds'
        }
      ].each do |carrier_context|
        it "prints #{carrier_context[:label]} carrier metadata" do
          subscriber.on_protocol_carrier(
            carrier_context.merge(
              direction: 'request',
              token: spnego_token,
              service_principal: 'cifs/fileserver.example.local@EXAMPLE.LOCAL'
            )
          )

          expect(output_text).to include("# Kerberos Carrier: #{carrier_context[:label]}")
          expect(output_text).to include("Protocol: #{carrier_context[:protocol]}")
          expect(output_text).to include("Carrier: #{carrier_context[:carrier]}")
          expect(output_text).to include("Field Name: #{carrier_context[:field_name]}")
          expect(output_text).to include("Blob Length: #{spnego_token.bytesize}")
          expect(output_text).to include('Token Type: SPNEGO NegTokenInit')
        end
      end

      context 'when a carrier token is a string-like binary object' do
        let(:trace_mode) { 'full' }
        let(:spnego_response_token) { build_spnego_neg_token_resp }

        it 'renders the token as a binary summary and preserves SPNEGO negState' do
          subscriber.on_protocol_carrier(
            protocol: 'SMB',
            direction: 'response',
            label: 'SMB Session Setup',
            carrier: 'SMB2 Session Setup security blob',
            field_name: 'buffer',
            token: binary_token_object(spnego_response_token),
            service_principal: 'cifs/dc01.msflab.test@MSFLAB.TEST'
          )

          expect(output_text).to include('# Kerberos Carrier: SMB Session Setup')
          expect(output_text).to include('Blob Length: 22')
          expect(output_text).to include("Token: [binary 22 bytes: #{spnego_response_token.unpack1('H*')}]")
          expect(output_text).to include('Token Type: SPNEGO NegTokenResp')
          expect(output_text).to include('Neg State: accept-completed')
          expect(output_text).not_to include('Neg State: unknown (accept-completed)')
        end
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

  def build_ap_req_trace_metadata
    service_name = Rex::Proto::Kerberos::Model::PrincipalName.new(
      name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
      name_string: ['cifs', 'fileserver.example.local']
    )
    client_name = Rex::Proto::Kerberos::Model::PrincipalName.new(
      name_type: Rex::Proto::Kerberos::Model::NameType::NT_PRINCIPAL,
      name_string: ['Administrator']
    )
    ticket = Rex::Proto::Kerberos::Model::Ticket.new(
      tkt_vno: 5,
      realm: 'EXAMPLE.LOCAL',
      sname: service_name,
      enc_part: Rex::Proto::Kerberos::Model::EncryptedData.new(
        etype: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
        kvno: 2,
        cipher: "\x22".b * 32
      )
    )
    checksum = Rex::Proto::Kerberos::Model::Checksum.new(
      type: Rex::Proto::Gss::KRB_AP_REQ_CHKSUM_TYPE,
      checksum: "\x00".b * 24
    )
    authenticator = Rex::Proto::Kerberos::Model::Authenticator.new(
      vno: 5,
      crealm: 'EXAMPLE.LOCAL',
      cname: client_name,
      checksum: checksum,
      cusec: 123_456,
      ctime: Time.utc(2026, 3, 7, 12, 0, 0),
      enc_key_usage: Rex::Proto::Kerberos::Crypto::KeyUsage::AP_REQ_AUTHENTICATOR,
      sequence_number: 1234
    )
    ap_req = Rex::Proto::Kerberos::Model::ApReq.new(
      pvno: 5,
      msg_type: Rex::Proto::Kerberos::Model::AP_REQ,
      options: 0x20000000,
      ticket: ticket,
      authenticator: Rex::Proto::Kerberos::Model::EncryptedData.new(
        etype: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
        cipher: "\x33".b * 32
      )
    )
    session_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
      type: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
      value: "\x11".b * 32
    )

    {
      ap_req: ap_req,
      authenticator: authenticator,
      ticket: ticket,
      session_key: session_key,
      client_principal: 'Administrator@EXAMPLE.LOCAL',
      service_principal: 'cifs/fileserver.example.local@EXAMPLE.LOCAL',
      spn: 'cifs/fileserver.example.local',
      realm: 'EXAMPLE.LOCAL',
      mutual_auth: true,
      use_session_key: true,
      use_subkey: false,
      ticket_flags: Rex::Proto::Kerberos::Model::TicketFlags.from_flags(
        [
          Rex::Proto::Kerberos::Model::TicketFlags::FORWARDABLE,
          Rex::Proto::Kerberos::Model::TicketFlags::RENEWABLE
        ]
      ),
      replay_detection: 'requested by GSS checksum flags',
      channel_binding: { present: false },
      delegated_credentials: { mode: 'never', requested: false, present: false }
    }
  end

  def build_gss_kerberos_token(ap_req_der)
    OpenSSL::ASN1::ASN1Data.new(
      [
        Rex::Proto::Gss::OID_KERBEROS_5,
        "\x01\x00".b + ap_req_der
      ],
      0,
      :APPLICATION
    ).to_der
  end

  def build_spnego_neg_token_init(gss_token)
    OpenSSL::ASN1::ASN1Data.new(
      [
        Rex::Proto::Gss::OID_SPNEGO,
        OpenSSL::ASN1::ASN1Data.new(
          [
            OpenSSL::ASN1::Sequence.new(
              [
                OpenSSL::ASN1::ASN1Data.new(
                  [
                    OpenSSL::ASN1::Sequence.new(
                      [
                        Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5
                      ]
                    )
                  ],
                  0,
                  :CONTEXT_SPECIFIC
                ),
                OpenSSL::ASN1::ASN1Data.new(
                  [
                    OpenSSL::ASN1::OctetString.new(gss_token)
                  ],
                  2,
                  :CONTEXT_SPECIFIC
                )
              ]
            )
          ],
          0,
          :CONTEXT_SPECIFIC
        )
      ],
      0,
      :APPLICATION
    ).to_der
  end

  def build_spnego_neg_token_resp
    "\xa1\x14\x30\x12\xa0\x03\x0a\x01\x00\xa1\x0b\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02".b
  end

  def binary_token_object(token)
    double('binary token', to_binary_s: token, bytesize: token.bytesize, to_s: token)
  end

  def build_ap_rep_message
    Rex::Proto::Kerberos::Model::ApRep.new(
      pvno: 5,
      msg_type: Rex::Proto::Kerberos::Model::AP_REP,
      enc_part: Rex::Proto::Kerberos::Model::EncryptedData.new(
        etype: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
        cipher: "\x44".b * 32
      )
    )
  end

  def build_enc_ap_rep_part
    Rex::Proto::Kerberos::Model::EncApRepPart.new(
      ctime: Time.utc(2026, 3, 7, 12, 0, 0),
      cusec: 123_456,
      subkey: Rex::Proto::Kerberos::Model::EncryptionKey.new(
        type: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
        value: "\x55".b * 32
      ),
      sequence_number: 1234
    )
  end

  def build_krb_error_message
    Rex::Proto::Kerberos::Model::KrbError.new(
      pvno: 5,
      msg_type: Rex::Proto::Kerberos::Model::KRB_ERROR,
      stime: Time.utc(2026, 3, 7, 12, 0, 0),
      susec: 123_456,
      error_code: Rex::Proto::Kerberos::Model::Error::ErrorCodes::KRB_AP_ERR_MODIFIED,
      realm: 'EXAMPLE.LOCAL',
      sname: Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
        name_string: ['cifs', 'fileserver.example.local']
      ),
      etext: 'Message stream modified',
      e_data: "\x60\x00\x00\xc0".b
    )
  end
end

# rubocop:enable Metrics/BlockLength
