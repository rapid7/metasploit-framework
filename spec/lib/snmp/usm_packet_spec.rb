require 'spec_helper'
require 'snmp'
require 'openssl'

RSpec.describe SNMP::UserBasedSecurityModel do
  include SNMP::BER

  subject(:usm) do
    described_class.new(
      username: 'testuser',
      security_level: security_level,
      auth_protocol: 'SHA1',
      auth_password: 'maplesyrup',
      priv_protocol: 'AES',
      priv_password: 'maplesyrup',
      context_name: ''
    )
  end

  let(:security_level) { 'authNoPriv' }
  let(:engine_id) { ['000000000000000000000002'].pack('H*') }

  # RFC 3414 Appendix A.3.2: SHA1 localized key for maplesyrup.
  let(:localized_key) do
    ['6695febc9288e36282235fc7151f128497b38f3f'].pack('H*')
  end

  before do
    usm.send(:synchronize_engine, engine_id, 5, 1000)
    allow(usm).to receive(:current_engine_time).and_return(1000)
  end

  # Constructs responses independently of the USM encoder.
  def response_packet(
    encrypted: false,
    signing_key: localized_key,
    username: 'testuser',
    context_engine_id: engine_id,
    context_name: ''
  )
    response = SNMP::Response.new(123, SNMP::VarBindList.new([]))
    scoped = encode_sequence(
      encode_octet_string(context_engine_id) +
      encode_octet_string(context_name) +
      response.encode
    )

    salt = ['0000000000000001'].pack('H*')
    if encrypted
      cipher = OpenSSL::Cipher.new('aes-128-cfb').encrypt
      cipher.padding = 0
      cipher.key = localized_key.byteslice(0, 16)
      cipher.iv = [5, 1000].pack('NN') + salt
      scoped = encode_octet_string(cipher.update(scoped) + cipher.final)
    end

    flags = encrypted ? 3 : 1
    header = encode_sequence(
      encode_integer(456) +
      encode_integer(8000) +
      encode_octet_string(flags.chr.b) +
      encode_integer(3)
    )

    empty_mac = "\x00".b * 12
    security = encode_sequence(
      encode_octet_string(engine_id) +
      encode_integer(5) +
      encode_integer(1000) +
      encode_octet_string(username) +
      encode_octet_string(empty_mac) +
      encode_octet_string(encrypted ? salt : ''.b)
    )

    packet = encode_sequence(
      encode_integer(3) +
      header +
      encode_octet_string(security) +
      scoped
    )

    marker = encode_octet_string(empty_mac)
    marker_offset = packet.index(marker)
    raise 'Test packet authentication field not found' unless marker_offset

    mac_offset = marker_offset + marker.bytesize - empty_mac.bytesize
    mac = OpenSSL::HMAC.digest('SHA1', signing_key, packet).byteslice(0, 12)
    packet[mac_offset, 12] = mac
    packet
  end

  def process_packet(packet)
    usm.process_response(
      packet,
      expected_message_id: 456,
      expected_request_id: 123
    )
  end

  describe 'authenticated response packets' do
    it 'accepts a correctly authenticated plaintext response' do
      message = process_packet(response_packet)

      expect(message.authenticated?).to be(true)
      expect(message.encrypted?).to be(false)
      expect(message.pdu).to be_a(SNMP::Response)
      expect(message.pdu.request_id).to eq(123)
      expect(message.pdu.error_status).to eq(:noError)
    end

    it 'rejects a packet modified after signing' do
      packet = response_packet
      packet.setbyte(packet.bytesize - 1, packet.getbyte(packet.bytesize - 1) ^ 1)

      expect do
        process_packet(packet)
      end.to raise_error(SNMP::AuthenticationError)
    end

    it 'rejects a packet signed with a different key' do
      packet = response_packet(signing_key: "\x01".b * 20)

      expect do
        process_packet(packet)
      end.to raise_error(SNMP::AuthenticationError)
    end

    it 'rejects a different username even with a valid signature' do
      packet = response_packet(username: 'otheruser')

      expect do
        process_packet(packet)
      end.to raise_error(SNMP::InvalidSecurityParameters)
    end

    it 'rejects an unexpected scoped context engine ID' do
      packet = response_packet(context_engine_id: 'otherengine')

      expect do
        process_packet(packet)
      end.to raise_error(SNMP::InvalidSecurityParameters)
    end

    it 'rejects an unexpected scoped context name' do
      packet = response_packet(context_name: 'othercontext')

      expect do
        process_packet(packet)
      end.to raise_error(SNMP::InvalidSecurityParameters)
    end
  end

  context 'when authentication and privacy are required' do
    let(:security_level) { 'authPriv' }

    it 'accepts an authenticated AES-encrypted response' do
      message = process_packet(response_packet(encrypted: true))

      expect(message.authenticated?).to be(true)
      expect(message.encrypted?).to be(true)
      expect(message.pdu).to be_a(SNMP::Response)
      expect(message.pdu.request_id).to eq(123)
    end

    it 'rejects an authenticated plaintext response' do
      expect do
        process_packet(response_packet)
      end.to raise_error(SNMP::DecryptionError)
    end
  end
end
