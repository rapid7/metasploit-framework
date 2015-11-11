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
        the TLS-250 and TLS-350 protocols.  This has been tested against
        GasPot, a honeypot meant to simulate ATGs; it has not been tested
        against anything else, so use at your own risk.
      },
      'Author'         =>
        [
          'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://community.rapid7.com/community/infosec/blog/2015/01/22/the-internet-of-gas-station-tank-gauges'],
          ['URL', 'http://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/the-gaspot-experiment'],
          ['URL', 'https://github.com/sjhilt/GasPot'],
          ['URL', 'http://www.veeder.com/us/automatic-tank-gauge-atg-consoles'],
          ['URL', 'http://www.chipkin.com/files/liz/576013-635.pdf'],
          ['URL', 'http://www.veeder.com/gold/download.cfm?doc_id=6227']
        ],
      'DefaultAction'  => 'INVENTORY',
      'Actions'        =>
        [
          [ 'ALARM',
            {
              'Description' => 'I30200 Sensor alarm history (untested)',
              'TLS-350_CMD' => "\x01I30200"
            }
          ],
          [ 'ALARM_RESET',
            {
              'Description' => 'IS00300 Remote alarm reset (untested)',
              'TLS-350_CMD' => "\x01IS00300"
            }
          ],
          [ 'DELIVERY',
            {
              'Description' => 'I20200 Delivery report',
              'TLS-350_CMD' => "\x01I20200"
            }
          ],
          [ 'INVENTORY',
            {
              'Description' => '200/I20100 In-tank inventory report',
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
          [ 'RELAY',
            {
              'Description' => 'I40600 Relay status (untested)',
              'TLS-350_CMD' => "\x01I40600"
            }
          ],
          [ 'RESET',
            {
              'Description' => 'IS00100 Reset (untested)',
              'TLS-350_CMD' => "\x01IS00100"
            }
          ],
          [ 'CLEAR_RESET',
            {
              'Description' => 'IS00200 Clear Reset Flag (untested)',
              'TLS-350_CMD' => "\x01IS00200"
            }
          ],
          [ 'SENSOR',
            {
              'Description' => 'I30100 Sensor status (untested)',
              'TLS-350_CMD' => "\x01I30100"
            }
          ],
          [ 'SENSOR_DIAG',
            {
              'Description' => 'IB0100 Sensor diagnostics (untested)',
              'TLS-350_CMD' => "\x01IB0100"
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
          [ 'SET_TIME',
            {
              'Description' => 'S50100 Set time of day (untested)',
              'TLS-350_CMD' => "\x01S50100"
            }
          ],
          [ 'STATUS',
            {
              'Description' => 'I20500 In-tank status report',
              'TLS-350_CMD' => "\x01I20500"
            }
          ],
          [ 'SYSTEM_STATUS',
            {
              'Description' => 'I10100 System status report (untested)',
              'TLS-350_CMD' => "\x01I10100"
            }
          ],
          [ 'TANK_ALARM',
            {
              'Description' => 'I20600 Tank alarm history (untested)',
              'TLS-350_CMD' => "\x01I20600"
            }
          ],
          [ 'TANK_DIAG',
            {
              'Description' => 'IA0100 Tank diagnostics (untested)',
              'TLS-350_CMD' => "\x01IA0100"
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
    fail "TANK_NUMBER #{tank_number} is invalid" if action.name == 'SET_TANK_NAME' && (tank_number < 0 || tank_number > 99)
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
        request = action.opts[protocol + '_CMD'] + "#{format('%02d', tank_number)}#{tank_name}\n"
        sock.put(request)
        disconnect
        connect
        sock.put(actions.find { |a| a.name == 'INVENTORY' }.opts[protocol + '_CMD'] + "\n")
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
