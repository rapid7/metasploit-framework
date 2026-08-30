# -*- coding: binary -*-
require 'rex/text'

module Rex
module Proto
module SMB
class Crypt

  @@loaded_openssl = false

  begin
    require 'openssl'
    @@loaded_openssl = true
  rescue ::Exception
  end

  # Return a signed SMB packet
  def self.sign_smb_packet(mackey, sequence_counter, data)
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
    seq = Rex::Text::pack_int64le(sequence_counter)
    netbios_hdr = data.slice!(0,4)
    data[14,8] = seq
    signature = OpenSSL::Digest::MD5.digest(mackey + data)[0,8]
    data[14,8] = signature
    netbios_hdr + data
  end

  def self.is_signature_correct?(mackey, sequence_counter, data)
    signature1 = data[18,8]
    signature2 = sign_smb_packet(mackey, sequence_counter, data.dup)[18,8]
    return signature1 == signature2
  end

end
end
end
end
