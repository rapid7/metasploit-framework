##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Encoder
  Rank = ExcellentRanking

  def initialize
    super(
      'Name'             => 'Python Chr Encoder',
      'Description'      => %q{
        This encodes bad chars with chr().
      },
      'Author'           => 'Ben Campbell',
      'Arch'             => ARCH_PYTHON,
      'Platform'         => 'python')
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)

    if state.badchars.include? '"'
      state.badchars.each_char do |c|
        buf.gsub!(c,"'+chr(#{c.ord})+'")
      end

      encoded = "exec('#{buf}')"
    else
      state.badchars.each_char do |c|
        buf.gsub!(c,"\"+chr(#{c.ord})+\"")
      end

      encoded = "exec(\"#{buf}\")"
    end

    encoded
  end

end

