##
# encoding: utf-8
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Veeder-Root Automatic Tank Gauge (ATG) Administrative Client',
      'Description'    => %q{
        This module acts as a simplistic administrative client for interfacing
        with Veeder-Root Automatic Tang Gauges (ATGs) or other devices speaking
        the TLS-250 and TLS-350 protocols.
       },
      'Author'         =>
        [
          'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'http://www.veeder.com/us/automatic-tank-gauge-atg-consoles']
      ],
      'DefaultAction'  => 'INVENTORY',
      'Actions'        =>
        [
          [ 'DELIVERY',
            {
              'Description' => 'I20200 Delivery report',
              'TLS-350_CMD' => "\x01I20200"
            }
          ],
          [ 'INVENTORY',
            {
              'Description' => 'I20100 In-tank inventory report',
              'TLS-250_CMD' => "\x01200",
              'TLS-350_CMD' => "\x01I20100"
            }
          ],
          [ 'LEAK',
            {
              'Description' => 'I20300 Leak report',
              'TLS-350_CMD' => "\x01I20300"
            }
          ],
          [ 'SHIFT',
            {
              'Description' => 'I20400 Shift report',
              'TLS-350_CMD' => "\x01I20400"
            }
          ],
          [ 'STATUS',
            {
              'Description' => 'I20500 In-tank status report',
              'TLS-350_CMD' => "\x01I20500"
            }
          ],
          [ 'VERSION',
            {
              'Description' => 'Version information',
              'TLS-250_CMD' => "\x01980",
              'TLS-350_CMD' => "\x01I90200"
            }
          ]
        ]
    )

    register_options(
      [
        Opt::RPORT(10001)
      ],
      self.class
    )
    deregister_options('SSL', 'SSLCipher', 'SSLVerifyMode', 'SSLVersion')

    register_advanced_options(
      [
        OptEnum.new('PROTOCOL', [true, 'The Veeder-Root TLS protocol to speak', 'TLS-350', %w(TLS-350 TLS-250)])
      ],
      self.class
    )
  end

  def setup
    proto_cmd = datastore['PROTOCOL'] + "_CMD"
    fail "#{action.name} not defined for #{datastore['PROTOCOL']}" unless action.opts.keys.include?(proto_cmd)
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(_host)
    begin
      connect
      sock.put(action.opts[datastore['PROTOCOL'] + '_CMD'])
      print_status("#{peer} #{datastore['PROTOCOL']} #{action.opts['Description']}:\n#{sock.get_once}")
    ensure
      disconnect
    end
  end
end
