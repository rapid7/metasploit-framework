##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Encoder
  Rank = ExcellentRanking

  def initialize
    super(
      'Name'             => 'Python Base64 Encoder',
      'Description'      => %q{
        This encodes the command as a base64 encoded command for python.
      },
      'Author'           => 'Ben Campbell',
      'Arch'             => ARCH_PYTHON,
      'Platform'         => 'python')
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    # Skip encoding for empty badchars
    if state.badchars.length == 0
      return buf
    elsif state.badchars.include?("'") && state.badchars.include?('"')
      raise EncodingError, "Cannot base64 with both single quote and double quote badchars."
    end

    base64 = encode_buf(buf)

    if state.badchars.include? '='
        while base64.include? '='
          buf << " "
          base64 = encode_buf(buf)
        end
    end

    if state.badchars.include? "'"
      if state.badchars =~ /[:; \{\},\[\]]/
        encoded = "exec(\"#{base64}\".decode(\"base64\"))"
      else
        encoded = "import sys;exec({2:str,3:lambda b:bytes(b,\"UTF-8\")}[sys.version_info[0]](\"#{base64}\").decode(\"base64\"))"
      end
    else
      if state.badchars =~ /[:; \{\},\[\]]/
        encoded = "exec('#{base64}'.decode('base64'))"
      else
        encoded = "import sys;exec({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('#{base64}').decode('base64'))"
      end
    end

    encoded
  end

  def encode_buf(buf)
    Rex::Text.encode_base64(buf)
  end

end

