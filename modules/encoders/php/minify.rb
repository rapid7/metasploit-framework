##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GreatRanking

  def initialize
    super(
      'Name' => 'PHP Minify Encoder',
      'Description' => %q{
        This encoder minifies a PHP payload by removing leasing spaces, trailing
        new lines, comments, ...
      },
      'Author' => 'Julien Voisin',
      'License' => BSD_LICENSE,
      'Arch' => ARCH_PHP)
  end

  def encode_block(_, buf)
    # Remove comments
    buf.gsub!(/^\s*#.*$/, '')

    # Remove spaces after keywords
    buf.gsub!(/^\s*(if|else|elsif|while|for|foreach)\s*\(/, '\1(')

    # Remove spaces before block opening
    buf.gsub!(/\s*{$/, '{')

    # Remove empty lines
    buf.squeeze!("\n")

    # Remove leading/trailing spaces
    buf.gsub!(/^[ \t]+/, '')

    # Remove new lines
    buf.gsub!(/([;{}])\n/, '\1')

    return buf
  end
end
