##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder

  # Set to ManualRanking because actually using ths encoder will
  # certainly destroy any possibility of a successful shell.
  #
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'The EICAR Encoder',
      'Description'      => %q{
        This encoder merely replaces the given payload with the EICAR test string.
        Note, this is sure to ruin your payload.

        Any content-aware firewall, proxy, IDS, or IPS that follows anti-virus
        standards should alert and do what it would normally do when malware is
        transmitted across the wire.
      },
      'Author'           => 'todb',
      'License'          => MSF_LICENSE,
      'Arch'             => ARCH_ALL,
      'EncoderType'      => Msf::Encoder::Type::Unspecified)

  end

  # Avoid stating the string directly, don't want to get caught by local
  # antivirus!
  def eicar_test_string
    obfus_eicar = ["x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar", "standard", "antivirus", "test", "file!$h+h*"]
    obfus_eicar.join("-").upcase
  end

  # TODO: add an option to merely prepend and not delete, using
  # prepend_buf. Now, technically, EICAR should be all by itself
  # and not part of a larger whole. Problem is, OptBool is
  # acting funny here as an encoder option.
  #
  def encode_block(state, buf)
    buf = eicar_test_string
  end
end
