##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Wireless Frame (File) Injector',
      'Description' => %q{
          Inspired by Josh Wright's file2air, this module writes
        wireless frames from a binary file to the air, allowing
        you to substitute some addresses before it gets sent.
        Unlike the original file2air (currently v1.1), this module
        *does* take into account the ToDS and FromDS flags in the
        frame when replacing any specified addresses.
      },
      # 11/03/2008
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    ))

    register_options([
        OptString.new('FILE', [true, 'Filename to write to the air']),
        OptString.new('ADDR_DST', [false, 'Target MAC (e.g. 00:DE:AD:BE:EF:00)']),
        OptString.new('ADDR_SRC', [false, 'Source MAC (e.g. 00:DE:AD:BE:EF:00)']),
        OptString.new('BSSID', [false, 'BSSID (e.g. 00:DE:AD:BE:EF:00)']),
        OptInt.new('NUM', [true, 'Number of frames to send', 1])
    ], self.class)
  end

  def run
    begin
      frame = File.read(datastore['FILE'])
    rescue ::Exception
      print_status("Couldn't read from \"#{datastore['FILE']}\": #{$!}")
      return
    end

    # Sending too much data can cause local problems, even if it's
    # less than the 802.11 MTU.  Gotta draw the line somewhere.
    if frame.length < 10 or frame.length > 1800
      print_status("Invalid frame size (should be 10-1800 bytes)")
      return
    end

    if datastore['BSSID'] or datastore['ADDR_DST'] or datastore['ADDR_SRC']
      if not substaddrs(frame)
        print_status("This module doesn't support modifying frames with both ToDS and FromDS set")
        return
      end
    end

    open_wifi

    print_status("Writing out #{datastore['NUM']} frames...")

    datastore['NUM'].times do
      wifi.write(frame)
    end

    close_wifi
  end

  def substaddrs(frame)
    tods = (frame[1] & 1) == 1
    fromds = (frame[1] & 2) == 2

    if tods
      if fromds
        # Not going to handle this 4-address special-case
        return nil
      else
        substaddr1(frame, datastore['BSSID'])
        substaddr2(frame, datastore['ADDR_SRC'])
        substaddr3(frame, datastore['ADDR_DST'])
      end
    else
      if fromds
        substaddr1(frame, datastore['ADDR_DST'])
        substaddr2(frame, datastore['BSSID'])
        substaddr3(frame, datastore['ADDR_SRC'])
      else
        substaddr1(frame, datastore['ADDR_DST'])
        substaddr2(frame, datastore['ADDR_SRC'])
        substaddr3(frame, datastore['BSSID'])
      end
    end

    true
  end

  def substaddr1(frame, addr)
    frame[4,6] = eton(addr) if addr
  end

  def substaddr2(frame, addr)
    frame[10,6] = eton(addr) if addr
  end

  def substaddr3(frame, addr)
    frame[16,6] = eton(addr) if addr
  end
end
