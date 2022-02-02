##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Veeder-Root Automatic Tank Gauge (ATG) Administrative Client',
      'Description'    => %q{
        This module acts as a simplistic administrative client for interfacing
        with Veeder-Root Automatic Tank Gauges (ATGs) or other devices speaking
        the TLS-250 and TLS-350 protocols.  This has been tested against
        GasPot and Conpot, both honeypots meant to simulate ATGs; it has not
        been tested against anything else, so use at your own risk.
      },
      'Author'         =>
        [
          'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://blog.rapid7.com/2015/01/22/the-internet-of-gas-station-tank-gauges'],
          ['URL', 'http://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/the-gaspot-experiment'],
          ['URL', 'https://github.com/sjhilt/GasPot'],
          ['URL', 'https://github.com/mushorg/conpot'],
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
              'Description' => 'S602 set tank name (use TANK_NUMBER and TANK_NAME options)',
              'TLS-350_CMD' => "\x01S602"
            }
          ],
          # [ 'SET_TIME',
          #   {
          #     'Description' => 'S50100 Set time of day (use TIME option) (untested)',
          #     'TLS-350_CMD' => "\x01S50100"
          #   }
          # ],
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
        OptString.new('TANK_NAME', [false, 'The tank name to set (use with SET_TANK_NAME, defaults to random)'])
      ]
    )
    deregister_options('SSL', 'SSLCipher', 'SSLVerifyMode', 'SSLVersion')

    register_advanced_options(
      [
        OptEnum.new('PROTOCOL', [true, 'The Veeder-Root TLS protocol to speak', 'TLS-350', %w(TLS-350 TLS-250)]),
        OptInt.new('TIMEOUT', [true, 'Time in seconds to wait for responses to our probes', 5])
      ]
    )
  end

  def setup
    # ensure that the specified command is implemented for the desired version of the TLS protocol
    unless action.opts.keys.include?(protocol_opt_name)
      fail_with(Failure::BadConfig, "#{action.name} not defined for #{protocol}")
    end

    # ensure that the tank number is set for the commands that need it
    if action.name == 'SET_TANK_NAME' && (tank_number < 0 || tank_number > 99)
      fail_with(Failure::BadConfig, "TANK_NUMBER #{tank_number} is invalid")
    end

    unless timeout > 0
      fail_with(Failure::BadConfig, "Invalid timeout #{timeout} -- must be > 0")
    end
  end

  def get_response(request)
    sock.put(request)
    response = sock.get_once(-1, timeout)
    response.strip!
    response += " (command not understood)" if response == "9999FF1B"
    response
  end

  def protocol
    datastore['PROTOCOL']
  end

  def protocol_opt_name
    protocol + '_CMD'
  end

  def tank_name
    @tank_name ||= (datastore['TANK_NAME'] ? datastore['TANK_NAME'] : Rex::Text.rand_text_alpha(16))
  end

  def tank_number
    datastore['TANK_NUMBER']
  end

  def time
    if datastore['TIME']
      Time.parse(datastore['TIME']).to_i
    else
      Time.now.to_i
    end
  end

  def timeout
    datastore['TIMEOUT']
  end

  def run_host(_host)
    begin
      connect
      case action.name
      when 'SET_TANK_NAME'
        # send the set tank name command to change the tank name(s)
        if tank_number == 0
          vprint_status("Setting all tank names to #{tank_name}")
        else
          vprint_status("Setting tank ##{tank_number}'s name to #{tank_name}")
        end
        request = "#{action.opts[protocol_opt_name]}#{format('%02d', tank_number)}#{tank_name}\n"
        sock.put(request)
        # reconnect
        disconnect
        connect
        # send an inventory probe to show that it succeeded
        inventory_probe = "#{actions.find { |a| a.name == 'INVENTORY' }.opts[protocol_opt_name]}\n"
        inventory_response = get_response(inventory_probe)
        message = "#{protocol} #{action.opts['Description']}:\n#{inventory_response}"
        if inventory_response.include?(tank_name)
          print_good message
        else
          print_warning message
        end
      else
        response = get_response("#{action.opts[protocol_opt_name]}\n")
        print_good("#{protocol} #{action.opts['Description']}:")
        print_line(response)
      end
    ensure
      disconnect
    end
  end
end
