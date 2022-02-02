# -*- coding: binary -*-

module Rex
module Proto
module IPMI
class Utils

  def self.checksum(data)
    sum = 0
    data.unpack("C*").each {|c| sum += c }
    sum = ~sum + 1
    sum & 0xff
  end

  def self.create_ipmi_getchannel_probe
    [   # Get Channel Authentication Capabilities
      0x06, 0x00, 0xff, 0x07, # RMCP Header
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x20, 0x18,
      0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5
    ].pack("C*")
  end

  # open rmcpplus_request
  def self.create_ipmi_session_open_request(console_session_id)
    head = [
      0x06, 0x00, 0xff, 0x07,   # RMCP Header
      0x06,                     # RMCP+ Authentication Type
      PAYLOAD_RMCPPLUSOPEN_REQ, # Payload Type
      0x00, 0x00, 0x00, 0x00,   # Session ID
      0x00, 0x00, 0x00, 0x00    # Sequence Number
    ].pack("C*")

    data =
    [   # Maximum access
      0x00, 0x00,
      # Reserved
      0x00, 0x00
    ].pack("C*") +
    console_session_id +
    [
      0x00, 0x00, 0x00, 0x08,
      0x01, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x08,
      # HMAC-SHA1
      0x01, 0x00, 0x00, 0x00,
      0x02, 0x00, 0x00, 0x08,
      # AES Encryption
      0x01, 0x00, 0x00, 0x00
    ].pack("C*")

    head + [data.length].pack('v') + data
  end


  # open rmcpplus_request with cipherzero
  def self.create_ipmi_session_open_cipher_zero_request(console_session_id)
    head = [
      0x06, 0x00, 0xff, 0x07,   # RMCP Header
      0x06,                     # RMCP+ Authentication Type
      PAYLOAD_RMCPPLUSOPEN_REQ, # Payload Type
      0x00, 0x00, 0x00, 0x00,   # Session ID
      0x00, 0x00, 0x00, 0x00    # Sequence Number
    ].pack("C*")

    data =
    [   # Maximum access
      0x00, 0x00,
      # Reserved
      0x00, 0x00
    ].pack("C*") +
    console_session_id +
    [
      0x00, 0x00, 0x00, 0x08,
      # Cipher 0
      0x00, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x08,
      # Cipher 0
      0x00, 0x00, 0x00, 0x00,
      0x02, 0x00, 0x00, 0x08,
      # No Encryption
      0x00, 0x00, 0x00, 0x00
    ].pack("C*")

    head + [data.length].pack('v') + data
  end

  def self.create_ipmi_rakp_1(bmc_session_id, console_random_id, username)
    head = [
      0x06, 0x00, 0xff, 0x07,  # RMCP Header
      0x06,                    # RMCP+ Authentication Type
      PAYLOAD_RAKP1,           # Payload Type
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
    ].pack("C*")

    data =
      [0x00, 0x00, 0x00, 0x00].pack("C*") +
      bmc_session_id +
      console_random_id +
      [
        0x14, 0x00, 0x00,
        username.length
      ].pack("C*") +
      username

    head + [data.length].pack('v') + data
  end


  def self.create_rakp_hmac_sha1_salt(con_sid, bmc_sid, con_rid, bmc_rid, bmc_gid, auth_level, username)
    con_sid +
    bmc_sid +
    con_rid +
    bmc_rid +
    bmc_gid +
    [ auth_level ].pack("C") +
    [ username.length ].pack("C") +
    username
  end

  def self.verify_rakp_hmac_sha1(salt, hash, password)
    OpenSSL::HMAC.digest('sha1', password, salt) == hash
  end

end
end
end
end
