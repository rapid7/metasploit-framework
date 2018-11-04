##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GreatRanking

  def initialize
    super(
      'Name'             => 'Ruby Md5 Encoder',
      'Description'      => %q{
        This encoder returns a Md5 string encapsulated in
        eval(%(Md5 encoded string).unpack(%(m0)).first).
      },
      'Author'           => 'Ismail Tasdelen',
      'References'  =>
        [
	  ['URL', 'https://www.linkedin.com/in/ismailtasdelen/'],
          ['URL', 'https://github.com/ismailtasdelen'],
        ],
      'License'          => BSD_LICENSE,
      'Arch'             => ARCH_RUBY)
  end

  def encode_block(state, buf)
    %w{( ) . % e v a l u n p c k m 0 f i r s t}.each do |c|
      raise BadcharError if state.badchars.include?(c)
    end

    md5 = Rex::Text.encode_md5(buf)

    state.badchars.each_byte do |byte|
      raise BadcharError if md5.include?(byte.chr)
    end

    return "eval(%(" + md5 + ").unpack(%(m0)).first)"
  end
end