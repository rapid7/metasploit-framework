##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Hardware::RFTransceiver::RFTransceiver

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'RF Transceiver Transmitter',
        'Description'   => %q{
            This module powers an HWBridge-connected radio transceiver,
            effectively transmitting on the frequency set by the FREQ option.

            NOTE: Users of this module should be aware of their local laws,
            regulations, and licensing requirements for transmitting on any
            given radio frequency.

        },
        'References'     =>
        [
          ['URL', 'https://github.com/AndrewMohawk/RfCatHelpers']
        ],
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('FREQ', [true, "Frequency to transmit on"]),
      OptInt.new('SECONDS', [false, "Seconds to transmit", 4]),
      OptInt.new('BAUD', [false, "Baud rate to use", 4800]),
      OptInt.new('POWER', [false, "Power level", 100]),
      OptInt.new('INDEX', [false, "USB Index to use", 0])
    ])

  end

  def run
    unless is_rf?
      print_error("Not an RF Transceiver")
      return
    end
    unless set_index(datastore['INDEX'])
      print_error("Couldn't set usb index to #{datastore['INDEX']}")
      return
    end
    set_modulation("ASK/OOK")
    set_freq(datastore['FREQ'])
    set_sync_mode(0)
    set_baud(datastore['BAUD'])
    set_channel_spc(24000)
    set_mode("idle")
    set_power(datastore['POWER'])

    print_status("Transmitting on #{datastore['FREQ']} for #{datastore['SECONDS']} seconds...")
    set_mode("tx")
    sleep(datastore['SECONDS'])
    print_status("Finished transmitting")
    set_mode("idle")
  end
end
