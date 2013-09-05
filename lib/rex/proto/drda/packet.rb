# -*- coding: binary -*-
require 'rex/proto/drda'

module Rex
module Proto
module DRDA

class Error < StandardError; end
class RespError < Error; end

# See:
# http://publib.boulder.ibm.com/infocenter/dzichelp/v2r2/index.jsp?topic=/com.ibm.db29.doc.drda/db2z_excsat.htm
class MGRLVLLS_PARAM < Struct.new(:length, :codepoint, :payload)
  def initialize(args={})
    self[:codepoint] = Constants::MGRLVLLS
    self[:payload] = "\x14\x03\x00\x0a\x24\x07\x00\x0a" +
      "\x14\x74\x00\x05\x24\x0f\x00\x08" +
      "\x14\x40\x00\x09\x1c\x08\x04\xb8"
    self[:length] = self[:payload].to_s.size+4
  end
  def to_s
    self.to_a.pack("nna*")
  end
end

# Currently, only takes a MGRLVLLS param. Extend the struct
# when more parameters are defined.
class EXCSAT_DDM < Struct.new(:length, :magic, :format, :correlid, :length2,
   :codepoint, :mgrlvlls)

  def initialize(args={})
    self[:magic] = 0xd0
    self[:format] = 0x41
    self[:correlid] = 1
    self[:codepoint] = Constants::EXCSAT
    self[:mgrlvlls] = args[:mgrlvlls] || MGRLVLLS_PARAM.new.to_s
    self[:length] = (10 + self[:mgrlvlls].to_s.size)
    self[:length2] = self[:length]-6
  end

  def to_s
    packstr = "nCCnnn"
    packstr += "a*"  # Pack smarter as more params are added.
    self.to_a.pack(packstr)
  end
end

# See http://publib.boulder.ibm.com/infocenter/dzichelp/v2r2/index.jsp?topic=/com.ibm.db29.doc.drda/db2z_accsec.htm
# for all sorts of info about SECMEC.
class SECMEC_PARAM < Struct.new(:length, :codepoint, :payload)
  def initialize(args={})
    self[:length] = 6
    self[:codepoint] = Constants::SECMEC
    self[:payload] = 3 # Plaintext username and password.
  end
  def to_s
    self.to_a.pack("nnn")
  end
end

# Relational Database name parameter.
class RDBNAM_PARAM < Struct.new(:length, :codepoint, :payload)
  def initialize(args={})
    self[:length] = 22 # Since the database name is padded out.
    self[:codepoint] = Constants::RDBNAM
    self[:payload] = encode(args[:payload].to_s)
  end

  def encode(str)
    Rex::Text.to_ebcdic([str].pack("A18"))
  end

  def payload=(str)
    self[:payload] = encode(str.to_s)
  end

  def to_s
    self.to_a.pack("nna18")
  end

end

# The ACCSEC DDM is responsible for picking the security mechanism (SECMEC)
# which, in our case, will always be plain text username and password. It
# also sets the relational database name (RDBNAM), if specified. You need
# one to login, but not to probe.
class ACCSEC_DDM < Struct.new(:length, :magic, :format, :correlid, :length2,
   :codepoint, :secmec, :rdbnam)
  def initialize(args={})
    self[:magic] = 0xd0
    self[:format] = args[:format] || 0x01
    self[:correlid] = 2
    self[:codepoint] = Constants::ACCSEC
    self[:secmec] = SECMEC_PARAM.new.to_s
    if args[:dbname] # Include a database name if we're given one.
      self[:rdbnam] = RDBNAM_PARAM.new(:payload => args[:dbname]).to_s
    end
    self[:length] =  10 + self[:secmec].to_s.size + self[:rdbnam].to_s.size
    self[:length2] = self[:length]-6
  end
  def dbname=(str)
    self[:rdbnam] = RDBNAM_PARAM.new(:payload => args[:dbname]).to_s
  end
  def to_s
    packstr = "nCCnnna6"
    packstr += "a22" if self[:rdbnam]
    self.to_a.pack(packstr)
  end
end

class DDM_PARAM < Struct.new(:length, :codepoint, :payload)

  def read(str="")
    raise DRDA::Error, "Input isn't a String." if !str.kind_of? String
    raise DRDA::RespError, "DDM_PARAM is too short" if str.size < 4
    (self[:length], self[:codepoint]) =
      str.unpack("nn")
    raise DRDA::RespError, "DDM_PARAM Length is too short" if self[:length] < 4
    rest = str[4,self[:length]-4] # If it's negative or whatever, it'll end up as "".
    self[:payload] = rest.to_s[0,self[:length]-4]
    return self
  end

  def to_s
    self.to_a.pack("nna*")
  end

end

class BASIC_DDM < Struct.new(:length, :magic, :format, :correlid,
  :length2, :codepoint, :payload)
  def initialize
    self[:payload] = []
  end

  def read(str="")
    self[:payload].clear
    raise DRDA::Error, "Input isn't a String." if !str.kind_of? String
    raise DRDA::RespError, "Response is too short." if str.size < 10
    (self[:length],self[:magic],self[:format],
     self[:correlid],self[:length2],self[:codepoint]) =
     str.unpack("nCCnnn")
    sanity_check
    rest = str[10,self[:length2]-4]
    i = 0
    while (i < rest.size)
      if self[:codepoint] == Constants::SQLCARD # These aren't DDM's.
        this_param = rest[i,self[:length]-10]
      else
        this_param = DDM_PARAM.new.read(rest[i,rest.size])
      end
      self[:payload] << this_param
      i += this_param.to_s.size
    end
    return self
  end

  # Just a quick test.
  def sanity_check
    if self[:length] < 10
      raise DRDA::RespError, "DDM Length is too short."
    elsif self[:length2] < 4
      raise DRDA::RespError, "DDM Length2 is too short."
    elsif self[:length]-6 != self[:length2]
      raise DRDA::RespError, "Codepoint: 0x#{self[:codepoint].to_s(16)} DDM Length2 (0x#{self[:length2].to_s(16)}) isn't six less than Length (0x#{self[:length].to_s(16)})"
    end
  end

  def to_s
    self.to_a.pack("nCCnnn") + self[:payload].map {|x| x.to_s}.join
  end

end

class SERVER_PACKET < Array

  def read(str="")
    raise DRDA::Error, "Input isn't a String." if !str.kind_of? String
    self.clear
    i = 0
    while(i < str.size)
      this_ddm = BASIC_DDM.new.read(str[i,str.size])
      self << this_ddm
      i += this_ddm.to_s.size
    end
    return self
  end

  def to_s; self.join; end
  def sz; self.to_s.size; end

end

class PASSWORD_PARAM < Struct.new(:length, :codepoint, :payload)
  def initialize(args={})
    self[:codepoint] = Constants::PASSWORD
    self[:payload] = Rex::Text.to_ebcdic(args[:payload].to_s)
    self[:length] = self[:payload].size + 4
  end
  def encode(str)
    Rex::Text.to_ebcdic(str)
  end
  def to_s
    self.to_a.pack("nna*")
  end
end

class USERID_PARAM < Struct.new(:length, :codepoint, :payload)
  def initialize(args={})
    self[:codepoint] = Constants::USERID
    self[:payload] = Rex::Text.to_ebcdic(args[:payload].to_s)
    self[:length] = self[:payload].size + 4
  end
  def encode(str)
    Rex::Text.to_ebcdic(str)
  end
  def to_s
    self.to_a.pack("nna*")
  end
end

class SECCHK_DDM < Struct.new(:length, :magic, :format, :correlid, :length2,
  :codepoint, :secmec, :rdbnam, :password, :userid)
  def initialize(args={}) # Takes :dbname, :dbpass, :dbuser
    self[:magic] = 0xd0
    self[:format] = 0x01
    self[:correlid] = 2
    self[:codepoint] = Constants::SECCHK
    self[:secmec] = SECMEC_PARAM.new.to_s
    if args[:dbname] # Include a database name if we're given one.
      self[:rdbnam] = RDBNAM_PARAM.new(:payload => args[:dbname]).to_s
    end
    self[:password] = PASSWORD_PARAM.new(:payload => args[:dbpass]).to_s
    self[:userid] = USERID_PARAM.new(:payload => args[:dbuser]).to_s
    self[:length] = ( 10 + self[:secmec].to_s.size + self[:rdbnam].to_s.size +
           self[:password].to_s.size + self[:userid].to_s.size )
    self[:length2] = self[:length]-6
  end
  def dbname=(str)
    self[:rdbnam] = RDBNAM_PARAM.new(:payload => args[:dbname]).to_s
  end
  def to_s
    packstr = "nCCnnna6"
    packstr += "a22" if self[:rdbnam]
    packstr += "a*a*" # username and password
    self.to_a.pack(packstr)
  end
end

end
end
end

