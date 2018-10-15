##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GreatRanking

  def initialize
    super(
      'Name'             => 'Ruby Base64 Encoder',
      'Description'      => %q{
        This encoder returns a base64 string encapsulated in
        eval(%(base64 encoded string).unpack(%(m0)).first).
      },
      'Author'           => 'Robin Stenvi <robin.stenvi[at]gmail.com>',
      'License'          => BSD_LICENSE,
      'Arch'             => ARCH_RUBY)
  end

  def encode_block(state, buf)
    %w{( ) . % e v a l u n p c k m 0 f i r s t}.each do |c|
      raise BadcharError if state.badchars.include?(c)
    end

    b64 = Rex::Text.encode_base64(buf)

    state.badchars.each_byte do |byte|
      raise BadcharError if b64.include?(byte.chr)
    end

    return "eval(%(" + b64 + ").unpack(%(m0)).first)"
  end
end
