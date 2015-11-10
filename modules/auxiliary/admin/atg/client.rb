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
          [ 'SET_TANK_NAME',
            {
              'Description' => 'S602 set tank name',
              'TLS-350_CMD' => "\x01S602"
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
        Opt::RPORT(10001),
        OptInt.new('TANK_NUMBER', [false, 'The tank number to operate on (use with SET_TANK_NAME, 0 to change all)', 1]),
        OptString.new('TANK_NAME', [false, 'The tank name to set (use with SET_TANK_NAME), defaults to random'])
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
    # ensure that the specified command is implemented for the desired version of the TLS protocol
    proto_cmd = protocol + "_CMD"
    fail "#{action.name} not defined for #{protocol}" unless action.opts.keys.include?(proto_cmd)

    # ensure that the tank number is set for the commands that need it
    if action.name == 'SET_TANK_NAME'
      fail "TANK_NUMBER #{tank_number} is invalid" if tank_number < 0 || tank_number > 99
    end
  end

  def protocol
    datastore['PROTOCOL']
  end

  def tank_name
    @tank_name ||= (datastore['TANK_NAME'] ? datastore['TANK_NAME'] : Rex::Text.rand_text_alpha(16))
  end

  def tank_number
    datastore['TANK_NUMBER']
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(_host)
    begin
      connect
      case action.name
      when 'SET_TANK_NAME'
        vprint_status("#{peer} -- setting tank ##{tank_number} to #{tank_name}")
        request = action.opts[protocol + '_CMD'] + "#{'%02d' % tank_number}#{tank_name}\n"
        sock.put(request)
        disconnect
        connect
        sock.put(actions.select { |a| a.name == 'INVENTORY' }.first.opts[protocol + '_CMD'] + "\n")
        print_status("#{peer} #{datastore['PROTOCOL']} #{action.opts['Description']}:\n#{sock.get_once}")
      else
        request = action.opts[datastore['PROTOCOL'] + '_CMD'] + "\n"
        sock.put(request)
        print_status("#{peer} #{datastore['PROTOCOL']} #{action.opts['Description']}:\n#{sock.get_once}")
      end
    ensure
      disconnect
    end
  end
end
