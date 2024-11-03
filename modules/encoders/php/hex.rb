##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GreatRanking

  def initialize
    super(
      'Name' => 'PHP Hex Encoder',
      'Description' => %q{
        This encoder returns a hex string encapsulated in
        eval(hex2bin()), increasing the size by a bit more than
        a factor two.
      },
      'Author' => 'Julien Voisin',
      'License' => BSD_LICENSE,
      'Arch' => ARCH_PHP)
    register_options(
      [
        OptBool.new('Compress', [ true, 'Compress the payload with zlib', false ]) # Disabled by default as it relies on having php compiled with zlib, which might not be available on come exotic setups.
      ],
      self.class
    )
  end

  def encode_block(state, buf)
    # Have to have these for the decoder stub, so if they're not available,
    # there's nothing we can do here.
    %w[e v a l h e x 2 b i n ( ) ;].uniq.each do |c|
      raise BadcharError if state.badchars.include?(c)
    end

    if datastore['Compress']
      %w[g z u n c o m p r e s s].uniq.each do |c|
        raise BadcharError if state.badchars.include?(c)
      end
    end

    # Modern versions of PHP choke on unquoted literal strings.
    quote = "'"
    if state.badchars.include?("'")
      raise BadcharError.new, "The #{name} encoder failed to encode the decoder stub without bad characters." if state.badchars.include?('"')

      quote = '"'
    end

    if datastore['Compress']
      buf = Zlib::Deflate.deflate(buf)
    end

    hex = buf.unpack1('H*')

    state.badchars.each_byte do |byte|
      # Last ditch effort, if any of the normal characters used by hex
      # are badchars, try to replace them with something that will become
      # the appropriate thing on the other side.
      next unless hex.include?(byte.chr)

      %w[c h r ( ) .].uniq.each do |c|
        raise BadcharError if state.badchars.include?(c)
      end
      hex.gsub!(byte.chr, "#{quote}.chr(#{byte}).#{quote}")
    end

    if datastore['Compress']
      return 'eval(gzuncompress(hex2bin(' + quote + hex + quote + ')));'
    else
      return 'eval(hex2bin(' + quote + hex + quote + '));'
    end
  end
end
