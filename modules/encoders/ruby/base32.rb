##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GreatRanking

  def initialize
    super(
      'Name'             => 'Ruby Base32 Encoder',
      'Description'      => %q{
        This encoder returns a Base32 string encapsulated in
        eval(%(Base32 encoded string).unpack(%(m0)).first).
      },
      'Author'           => 'Ismail Tasdelen',
      'License'          => BSD_LICENSE,
      'Arch'             => ARCH_RUBY)
  end

  def encode_block(state, buf)
    %w{( ) . % e v a l u n p c k m 0 f i r s t}.each do |c|
      raise BadcharError if state.badchars.include?(c)
    end

    Base32 = Rex::Text.encode_Base32(buf)

    state.badchars.each_byte do |byte|
      raise BadcharError if Base32.include?(byte.chr)
    end

    return "eval(%(" + Base32 + ").unpack(%(m0)).first)"
  end
end
