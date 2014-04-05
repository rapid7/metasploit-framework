# -*- coding: binary -*-
require 'net/ssh'
require 'rex'

module Net
module SSH

# A place to define convenience utils for Net:SSH
module Utils
class Key
  class << self

  # Returns the fingerprint of a key file or key data. Usage:
  #   Net::SSH::Utils::Key.fingerprint(:file => "id_rsa")
  #   => "af:76:e4:f8:37:7b:52:8c:77:61:5b:d3:b0:d3:05:e4"
  # 
  # If both :file and :data are provided, :data will be read.
  # :format may be one of :binary, :compact, or nil (in which case colon-delimited will be returned)
  # If the key is a public key, it must be declared as such by :public => true. Default is private.
  def fingerprint(args={})
    file = args[:file] || args[:f]
    data = args[:data] || args[:d]
    method = ((args[:public] || args[:pub]) ? :load_public_key : :load_private_key) 
    format = args[:format] 
    if data
      fd = Tempfile.new("msf3-sshkey-temp-")
      fd.binmode
      fd.write data
      fd.flush
      file = fd.path
    end
    key = KeyFactory.send method,file
    fp = key.fingerprint
    case args[:format]
    when :binary,:bin,:b
      return fp.split(":").map {|x| x.to_i(16)}.pack("C16")
    when :compact,:com,:c
      return fp.split(":").join
    else
      return fp
    end
  end

end
end
end
end
end
