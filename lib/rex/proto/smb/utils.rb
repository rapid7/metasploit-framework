# -*- coding: binary -*-
require 'rex/text'
require 'rex/proto/smb/constants'

module Rex
module Proto
module SMB
class Utils

CONST = Rex::Proto::SMB::Constants

  # Creates an access mask for use with the CLIENT.open() call based on a string
  def self.open_mode_to_access(str)
    access = CONST::OPEN_ACCESS_READ | CONST::OPEN_SHARE_DENY_NONE
    str.each_byte { |c|
      case [c].pack('C').downcase
        when 'w'
          access |= CONST::OPEN_ACCESS_READWRITE
      end
    }
    return access
  end

  # Creates a mode mask for use with the CLIENT.open() call based on a string
  def self.open_mode_to_mode(str)
    mode = 0

    str.each_byte { |c|
      case [c].pack('C').downcase
        when 'x' # Fail if the file already exists
          mode |= CONST::OPEN_MODE_EXCL
        when 't' # Truncate the file if it already exists
          mode |= CONST::OPEN_MODE_TRUNC
        when 'c' # Create the file if it does not exist
          mode |= CONST::OPEN_MODE_CREAT
        when 'o' # Just open the file, clashes with x
          mode |= CONST::OPEN_MODE_OPEN
      end
    }

    return mode
  end

  # Returns a disposition value for smb.create based on permission string
  def self.create_mode_to_disposition(str)
    str.each_byte { |c|
      case [c].pack('C').downcase
        when 'c' # Create the file if it does not exist
          return CONST::CREATE_ACCESS_OPENCREATE
        when 'o' # Just open the file and fail if it does not exist
          return CONST::CREATE_ACCESS_EXIST
      end
    }

    return CONST::CREATE_ACCESS_OPENCREATE
  end

  # NOTE: the difference below came from: Time.utc("1970-1-1") - Time.utc("1601-1-1")

  # Convert a 64-bit signed SMB time to a unix timestamp
  def self.time_smb_to_unix(thi, tlo)
    (((thi << 32) + tlo) / 10000000) - 11644473600
  end

  # Convert a unix timestamp to a 64-bit signed server time
  def self.time_unix_to_smb(unix_time)
    t64 = (unix_time + 11644473600) * 10000000
    thi = (t64 & 0xffffffff00000000) >> 32
    tlo = (t64 & 0x00000000ffffffff)
    return [thi, tlo]
  end

  # Convert a name to its NetBIOS equivalent
  def self.nbname_encode(str)
    encoded = ''
    for x in (0..15)
      if (x >= str.length)
        encoded << 'CA'
      else
        c = str[x, 1].upcase[0,1].unpack('C*')[0]
        encoded << [ (c / 16) + 0x41, (c % 16) + 0x41 ].pack('CC')
      end
    end
    return encoded
  end

  # Convert a name from its NetBIOS equivalent
  def self.nbname_decode(str)
    decoded = ''
    str << 'A' if str.length % 2 != 0
    while (str.length > 0)
      two = str.slice!(0, 2).unpack('C*')
      if (two.length == 2)
        decoded << [ ((two[0] - 0x41) * 16) + two[1] - 0x41 ].pack('C')
      end
    end
    return decoded
  end


end
end
end
end
