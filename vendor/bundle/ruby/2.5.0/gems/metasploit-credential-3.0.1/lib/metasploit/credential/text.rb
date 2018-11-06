# Helper module that contains methods for manipulating text into different formats.
module Metasploit::Credential::Text
  # Turn non-printable chars into hex representations, leaving others alone
  # If +whitespace+ is true, converts whitespace (0x20, 0x09, etc) to hex as
  # well.
  # @param [String] str the string to do substitution on
  # param [Boolean] whitespace converts whitespace to ASCII-safe hex if true, ignores if false
  # @return [String]
  def self.ascii_safe_hex(str, whitespace=false)
    if whitespace
      str.gsub(/([\x00-\x20\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0] }
    else
      str.gsub(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0]}
    end
  end

  # Convert hex into characters
  # @return [String]
  def self.dehex(str)
    hexen = str.scan(/\x5cx[0-9a-fA-F]{2}/n)
    hexen.each { |h|
      str.gsub!(h,h[2,2].to_i(16).chr)
    }
    str
  end

end