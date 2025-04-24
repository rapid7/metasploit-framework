##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GoodRanking

  BASE64_BYTES = [
    'A'.ord...'Z'.ord,
    'a'.ord...'z'.ord,
    '0'.ord...'9'.ord
  ].map(&:to_a).flatten + '+/='.bytes

  def initialize
    super(
      'Name' => 'Base64 Command Encoder',
      'Description' => %q{
        This encoder uses base64 encoding to avoid bad characters.
      },
      'Author' => 'Spencer McIntyre',
      'Arch' => ARCH_CMD,
      'Platform' => %w[bsd bsdi linux osx solaris unix],
      'EncoderType' => Msf::Encoder::Type::CmdPosixBase64)

    register_advanced_options(
      [
        OptString.new('Base64Decoder', [ false, 'The binary to use for base64 decoding', '', %w[base64 base64-long base64-short openssl] ])
      ]
    )
  end

  #
  # Encodes the payload
  # All unnecessary spaces from your payload inside the () are removed to avoid shell POSIX command lauguage conflicts
  # The only things allowed after compound commands are redirections, shell keywords, and the various command separators
  # such as (;, &, |, &&, ||)
  #
  def encode_block(state, buf)
    return buf if (buf.bytes & state.badchars.bytes).empty?

    raise EncodingError if (state.badchars.bytes & BASE64_BYTES).any?
    raise EncodingError if state.badchars.include?('-')

    ifs_encode_spaces = state.badchars.include?(' ')
    raise EncodingError if ifs_encode_spaces && (state.badchars.bytes & '${}'.bytes).any?

    base64_buf = Base64.strict_encode64(buf)
    case datastore['Base64Decoder']
    when 'base64'
      raise EncodingError if (state.badchars.bytes & '(|)'.bytes).any?

      base64_decoder = '(base64 --decode||base64 -d)'
    when 'base64-long'
      base64_decoder = 'base64 --decode'
    when 'base64-short'
      base64_decoder = 'base64 -d'
    when 'openssl'
      base64_decoder = 'openssl enc -base64 -d'
    else
      # find a decoder at runtime if we can use the necessary characters
      if (state.badchars.bytes & '(|)>/&'.bytes).empty?
        base64_decoder = '((command -v base64>/dev/null&&(base64 --decode||base64 -d))||(command -v openssl>/dev/null&&openssl enc -base64 -d))'
      elsif (state.badchars.bytes & '(|)'.bytes).empty?
        base64_decoder = '(base64 --decode||base64 -d)'
      else
        base64_decoder = 'openssl enc -base64 -d'
      end
    end

    if (state.badchars.bytes & '|'.bytes).empty?
      buf = "echo #{base64_buf}|#{base64_decoder}|sh"
    elsif (state.badchars.bytes & '<()'.bytes).empty?
      buf = "sh < <(#{base64_decoder} < <(echo #{base64_buf}))"
    elsif (state.badchars.bytes & '<`\''.bytes).empty?
      buf = "sh<<<`#{base64_decoder}<<<'#{base64_buf}'`"
    else
      raise EncodingError
    end

    buf = buf.gsub(/ +/, '${IFS}') if ifs_encode_spaces
    buf
  end
end
