# -*- coding: binary -*-

require 'spec_helper'

# A behavioral contract for the OPC-UA endpoint scanner, written against the
# implementation that parsed the protocol inline and kept unchanged across the
# port onto Rex::Proto::OpcUa.
#
# The point of it is that the port is invisible from outside the module: the
# same captured server produces the same console narration, in the same order,
# and the same rows in the database. Everything asserted here is either a string
# a user reads, a value the documentation describes, or a ceiling that is the
# only thing standing between a hostile response and unbounded allocation.
#
# The whole conversation is replayed from spec/file_fixtures/opc_ua, so this
# exercises the real HEL, OPN and GetEndpoints handling end to end rather than
# any one method of it. See spec/file_fixtures/opc_ua/README.md for provenance.
RSpec.describe 'scanner/scada/opcua_endpoint_enum' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:scanner) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/scada/opcua_endpoint_enum'
    )
  end

  def fixture(name)
    File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', name))
  end

  let(:ack) { fixture('ack_node_opcua.bin') }
  let(:open_response) { fixture('open_secure_channel_response_node_opcua.bin') }
  let(:get_endpoints_response) { fixture('get_endpoints_response_node_opcua.bin') }

  # Everything the server says, in the order it says it. The module reads
  # exactly what it needs before sending the next request, so one buffer serves
  # the whole exchange.
  let(:conversation) { ack + open_response + get_endpoints_response }

  # Stands in for the module's socket. Only put and get_once are used, and
  # get_once returns nil once the bytes run out, which is what a Rex socket does
  # when nothing arrives before its timeout.
  let(:sent) { [] }

  # Each element is the length a read asked for, so a ceiling can be shown to
  # bite before the module allocates anything on the strength of the number the
  # server sent.
  let(:reads) { [] }

  def socket_over(bytes)
    written = sent
    asked = reads
    Class.new do
      define_method(:initialize) { @buffer = bytes.dup.b }
      define_method(:put) { |data| written << data.dup.b }
      define_method(:get_once) do |length, _timeout = nil|
        asked << length
        @buffer.empty? ? nil : @buffer.slice!(0, length)
      end
    end.new
  end

  # Console narration, captured as [level, message] before
  # Msf::Auxiliary::Scanner prepends the ip:port that the documentation shows.
  let(:output) { [] }

  # Database writes, captured as [method, arguments].
  let(:reports) { [] }

  before do
    scanner.datastore['RHOST'] = '192.0.2.1'
    scanner.datastore['RPORT'] = 4840
    scanner.datastore['VERBOSE'] = true

    allow(scanner).to receive(:connect)
    allow(scanner).to receive(:disconnect)

    %i[print_status print_good print_error print_warning vprint_status vprint_good vprint_error].each do |level|
      allow(scanner).to receive(level) { |message| output << [level, message] }
    end

    %i[report_service report_note report_vuln].each do |report|
      allow(scanner).to receive(report) { |args| reports << [report, args] }
    end
  end

  def run_against(bytes)
    allow(scanner).to receive(:sock).and_return(socket_over(bytes))
    scanner.run_host('192.0.2.1')
  end

  def report_for(kind)
    reports.find { |name, _| name == kind }&.last
  end

  describe 'a successful enumeration of the captured server' do
    before { run_against(conversation) }

    # Constraint 1. Every one of these appears in the Scenarios section of
    # documentation/modules/auxiliary/scanner/scada/opcua_endpoint_enum.md. A
    # change here means the documentation is wrong, silently.
    it 'narrates the scan with the exact strings the documentation shows' do
      expect(output).to eq [
        [:vprint_good, 'OPC-UA Hello acknowledged, opening secure channel'],
        [:print_good, 'OPC-UA server enumerated - 7 endpoint(s), 1 unauthenticated and unencrypted'],
        [:print_status, '  [0] opc.tcp://ua-node:4840/UA/BackdraftTest'],
        [:print_status, '      security: None/None  identity: UserName, Certificate, Anonymous'],
        [:print_warning, '      endpoint accepts anonymous clients over an unencrypted channel'],
        [:print_status, '  [1] opc.tcp://ua-node:4840/UA/BackdraftTest'],
        [:print_status, '      security: Basic256Sha256/Sign  identity: UserName, Certificate, Anonymous'],
        [:print_status, '  [2] opc.tcp://ua-node:4840/UA/BackdraftTest'],
        [:print_status, '      security: Aes128_Sha256_RsaOaep/Sign  identity: UserName, Certificate, Anonymous'],
        [:print_status, '  [3] opc.tcp://ua-node:4840/UA/BackdraftTest'],
        [:print_status, '      security: Aes256_Sha256_RsaPss/Sign  identity: UserName, Certificate, Anonymous'],
        [:print_status, '  [4] opc.tcp://ua-node:4840/UA/BackdraftTest'],
        [:print_status, '      security: Basic256Sha256/SignAndEncrypt  identity: UserName, Certificate, Anonymous'],
        [:print_status, '  [5] opc.tcp://ua-node:4840/UA/BackdraftTest'],
        [
          :print_status,
          '      security: Aes128_Sha256_RsaOaep/SignAndEncrypt  identity: UserName, Certificate, Anonymous'
        ],
        [:print_status, '  [6] opc.tcp://ua-node:4840/UA/BackdraftTest'],
        [
          :print_status,
          '      security: Aes256_Sha256_RsaPss/SignAndEncrypt  identity: UserName, Certificate, Anonymous'
        ],
        [:print_status, '  ApplicationUri: urn:ua-node:NodeOPCUA-Server'],
        [:print_status, '  ProductUri: NodeOPCUA-Server']
      ]
    end

    it 'sends a HEL, an OPN, a GetEndpoints MSG and a CLO, in that order' do
      expect(sent.map { |frame| frame.byteslice(0, 4) }).to eq %w[HELF OPNF MSGF CLOF]
    end

    # The declared size of every request has to match what was actually written,
    # or the server reads the next request as the tail of this one.
    it 'declares a MessageSize matching the bytes it wrote' do
      expect(sent.map { |frame| frame.byteslice(4, 4).unpack1('V') }).to eq sent.map(&:bytesize)
    end

    # The channel the server issued has to be quoted back on every message sent
    # on it. Both are 6 and 1 in the capture.
    it 'quotes the SecureChannelId and TokenId the server issued' do
      expect(sent.drop(2).map { |frame| frame.byteslice(8, 8).unpack('V2') }).to eq [[6, 1], [6, 1]]
    end

    it 'reports the service' do
      expect(report_for(:report_service)).to eq(
        host: '192.0.2.1',
        port: 4840,
        proto: 'tcp',
        name: 'opc-ua',
        info: 'OPC-UA server, 7 endpoint(s), ApplicationUri urn:ua-node:NodeOPCUA-Server'
      )
    end

    it 'reports the vulnerability for the unauthenticated endpoint' do
      vuln = report_for(:report_vuln)

      expect(vuln[:host]).to eq '192.0.2.1'
      expect(vuln[:port]).to eq 4840
      expect(vuln[:proto]).to eq 'tcp'
      expect(vuln[:name]).to eq 'OPC-UA endpoint accepting anonymous identity without encryption'
      expect(vuln[:info]).to eq '1 of 7 advertised endpoint(s) accept the Anonymous user identity token ' \
                                'over a channel with MessageSecurityMode None'
    end

    # Constraint 3. report_note serialises this into the database and the
    # documentation describes its shape, so the keys, their order and the types
    # of their values are all part of the contract.
    describe 'the opcua.endpoints note' do
      let(:note) { report_for(:report_note) }
      let(:endpoints) { note[:data][:endpoints] }

      it 'is filed under the documented type with the documented update policy' do
        expect(note[:host]).to eq '192.0.2.1'
        expect(note[:port]).to eq 4840
        expect(note[:proto]).to eq 'tcp'
        expect(note[:type]).to eq 'opcua.endpoints'
        expect(note[:update]).to eq :unique_data
      end

      it 'carries one entry per endpoint' do
        expect(endpoints.length).to eq 7
      end

      it 'keys every endpoint identically, in the documented order' do
        expect(endpoints.map(&:keys).uniq).to eq [
          %i[
            endpoint_url
            application_uri
            product_uri
            application_name
            server_certificate_len
            security_mode
            security_mode_name
            security_policy_uri
            security_policy_name
            user_tokens
            security_level
          ]
        ]
      end

      it 'keys every user token identically, in the documented order' do
        expect(endpoints.flat_map { |ep| ep[:user_tokens].map(&:keys) }.uniq)
          .to eq [%i[policy_id token_type token_type_name]]
      end

      it 'gives every value the documented type' do
        endpoints.each do |ep|
          expect(ep[:endpoint_url]).to be_a String
          expect(ep[:application_uri]).to be_a String
          expect(ep[:product_uri]).to be_a String
          expect(ep[:application_name]).to be_a String
          expect(ep[:server_certificate_len]).to be_an Integer
          expect(ep[:security_mode]).to be_an Integer
          expect(ep[:security_mode_name]).to be_a String
          expect(ep[:security_policy_uri]).to be_a String
          expect(ep[:security_policy_name]).to be_a String
          expect(ep[:user_tokens]).to be_an Array
          expect(ep[:security_level]).to be_an Integer

          ep[:user_tokens].each do |token|
            expect(token[:policy_id]).to be_a String
            expect(token[:token_type]).to be_an Integer
            expect(token[:token_type_name]).to be_a String
          end
        end
      end

      it 'carries the values the captured server sent' do
        expect(endpoints.map { |ep| ep[:security_mode_name] })
          .to eq %w[None Sign Sign Sign SignAndEncrypt SignAndEncrypt SignAndEncrypt]
        expect(endpoints.map { |ep| ep[:security_policy_name] })
          .to eq %w[
            None Basic256Sha256 Aes128_Sha256_RsaOaep Aes256_Sha256_RsaPss
            Basic256Sha256 Aes128_Sha256_RsaOaep Aes256_Sha256_RsaPss
          ]
        expect(endpoints.map { |ep| ep[:security_level] }).to eq [1, 106, 105, 107, 206, 205, 207]
        expect(endpoints.map { |ep| ep[:user_tokens].length }).to eq [5, 3, 3, 3, 3, 3, 3]
      end

      # server_certificate_len is a length rather than the certificate itself,
      # so the note stays small and carries no key material into the database.
      it 'records the certificate length rather than the certificate' do
        expect(endpoints.map(&:keys).flatten).not_to include :server_certificate
        expect(endpoints.map { |ep| ep[:server_certificate_len] }).to all(eq(1078))
      end

      it 'names the token types the first endpoint accepts' do
        expect(endpoints.first[:user_tokens].map { |token| token[:token_type_name] })
          .to eq %w[UserName UserName Certificate Certificate Anonymous]
      end

      it 'records the policy ids verbatim' do
        expect(endpoints.first[:user_tokens].map { |token| token[:policy_id] }).to eq %w[
          username_basic256Sha256
          username_aes128Sha256RsaOaep
          certificate_basic256Sha256
          certificate_aes128Sha256RsaOaep
          anonymous
        ]
      end
    end
  end

  # Constraint 1 again, for the paths that produce no endpoints. These strings
  # are what a user sees against a host that is not an OPC-UA server, or is one
  # that will not talk, and they are the ones the documentation quotes.
  describe 'the paths that give up' do
    it 'says so when the host never answers the Hello' do
      run_against(''.b)

      expect(output).to eq [[:vprint_status, 'No OPC-UA response to HEL']]
    end

    it 'reports an ERR in answer to the Hello with its StatusCode name' do
      err = 'ERRF'.b + [16].pack('V') + [0x807D0000].pack('V') + [-1].pack('l<')
      run_against(err)

      expect(output).to eq [[:print_status, 'OPC-UA server present but refused the Hello - Bad_TcpServerTooBusy']]
    end

    it 'reports an ERR reason when the server supplies one' do
      reason = 'too many clients'
      err = 'ERRF'.b + [16 + reason.bytesize].pack('V') +
            [0x807D0000].pack('V') + [reason.bytesize].pack('l<') + reason
      run_against(err)

      expect(output).to eq [
        [:print_status, "OPC-UA server present but refused the Hello - Bad_TcpServerTooBusy - #{reason}"]
      ]
    end

    it 'says so when something that is not OPC-UA answers' do
      run_against('HTTP'.b + [47].pack('V') + ('x' * 39))

      expect(output).to eq [[:vprint_status, 'Non-OPC-UA response (type="HTT")']]
    end

    # 'no response' is the detail wording for a channel that never opens.
    it "uses 'no response' as the detail when the channel never opens" do
      run_against(ack)

      expect(output).to eq [
        [:vprint_good, 'OPC-UA Hello acknowledged, opening secure channel'],
        [
          :print_status,
          'OpenSecureChannel with SecurityPolicy=None failed (no response); endpoints cannot be enumerated'
        ]
      ]
    end

    it "uses 'no response' as the detail when GetEndpoints goes unanswered" do
      run_against(ack + open_response)

      expect(output.last).to eq [:print_error, 'GetEndpoints failed: no response']
    end

    it 'writes nothing to the database when it gives up' do
      run_against(ack)

      expect(reports).to be_empty
    end
  end

  # Constraint 2. Msf::Auxiliary::Scanner rescues ::RuntimeError in its per host
  # loop and re-raises it, which ends the sweep rather than moving to the next
  # host. Every error the library raises is one, so run_host has to contain them
  # or a single malformed server takes the whole scan down with it.
  describe 'containing library errors' do
    it 'raises errors that Msf::Auxiliary::Scanner would re-raise out of its host loop' do
      expect(Rex::Proto::OpcUa::Error::OpcUaError.ancestors).to include ::RuntimeError
    end

    it 'does not let a library error escape run_host' do
      allow(scanner).to receive(:report_endpoints)
        .and_raise(Rex::Proto::OpcUa::Error::FramingError, 'escaped')

      expect { run_against(conversation) }.not_to raise_error
    end

    it 'does not let a malformed record escape run_host' do
      allow(scanner).to receive(:report_endpoints).and_raise(BinData::ValidityError, 'escaped')

      expect { run_against(conversation) }.not_to raise_error
    end

    it 'disconnects even when an error escapes' do
      allow(scanner).to receive(:report_endpoints)
        .and_raise(Rex::Proto::OpcUa::Error::FramingError, 'escaped')

      expect(scanner).to receive(:disconnect)
      run_against(conversation)
    end
  end

  # Constraint 4. These are the only thing between the module and a response
  # that claims to be larger than memory.
  describe 'the ceilings on a hostile response' do
    it 'keeps a message ceiling of 4 MiB' do
      expect(Rex::Proto::OpcUa::Tcp::MAX_MESSAGE_SIZE).to eq 4 * 1024 * 1024
    end

    it 'keeps a chunk ceiling of 64' do
      expect(Rex::Proto::OpcUa::Tcp::MAX_CHUNKS).to eq 64
    end

    it 'keeps an endpoint ceiling of 64' do
      expect(Rex::Proto::OpcUa::Services::MAX_ENDPOINTS).to eq 64
    end

    it 'keeps a ceiling of 512 on every other array' do
      expect(Rex::Proto::OpcUa::Types::OpcUaArray::DEFAULT_MAX_LENGTH).to eq 512
    end

    # The arrays nested inside the endpoint array carry their own, tighter
    # ceilings, because the endpoint ceiling does not bound them: without these
    # the worst case is 64 endpoints times 512 elements.
    it 'caps the arrays nested inside an endpoint below the general ceiling' do
      expect(Rex::Proto::OpcUa::Services::MAX_USER_TOKENS)
        .to be <= Rex::Proto::OpcUa::Types::OpcUaArray::DEFAULT_MAX_LENGTH
      expect(Rex::Proto::OpcUa::Services::MAX_DISCOVERY_URLS)
        .to be <= Rex::Proto::OpcUa::Types::OpcUaArray::DEFAULT_MAX_LENGTH
    end

    # The read that matters is the one that never happens: the size is believed
    # only far enough to reject it, so the header is read and nothing else.
    it 'never reads the body of a message that declares more than the ceiling' do
      run_against('ACKF'.b + [Rex::Proto::OpcUa::Tcp::MAX_MESSAGE_SIZE + 1].pack('V'))

      expect(reads).to eq [Rex::Proto::OpcUa::Tcp::HEADER_LEN]
      expect(output).to eq [[:vprint_status, 'No OPC-UA response to HEL']]
    end

    it 'gives up on a response that never sends a final chunk' do
      chunk = 'MSGC'.b + [8 + 16 + 1].pack('V') + [6, 1, 1, 1].pack('V4') + 'x'
      run_against(ack + open_response + (chunk * Rex::Proto::OpcUa::Tcp::MAX_CHUNKS))

      expect(output.last).to eq [:print_error, 'GetEndpoints failed: response exceeded the 64 chunk ceiling']
    end

    # The endpoint count sits 52 bytes into the captured message, after the
    # framing, the TypeId and the ResponseHeader. Claiming one more than the
    # ceiling has to fail before a single EndpointDescription is built.
    it 'refuses an endpoint count above the ceiling' do
      oversize = get_endpoints_response.dup
      oversize[52, 4] = [Rex::Proto::OpcUa::Services::MAX_ENDPOINTS + 1].pack('l<')
      run_against(ack + open_response + oversize)

      expect(output.last.first).to eq :print_error
      expect(output.last.last).to start_with 'Malformed OPC-UA response: array length 65 exceeds'
    end

    it 'writes nothing to the database when a response is refused' do
      oversize = get_endpoints_response.dup
      oversize[52, 4] = [Rex::Proto::OpcUa::Services::MAX_ENDPOINTS + 1].pack('l<')
      run_against(ack + open_response + oversize)

      expect(reports).to be_empty
    end
  end
end
