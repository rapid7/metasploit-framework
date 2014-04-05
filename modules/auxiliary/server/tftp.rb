##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/tftp'
require 'tmpdir'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TFTPServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'TFTP File Server',
      'Description'    => %q{
        This module provides a TFTP service
      },
      'Author'      => [ 'jduck', 'todb' ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )

    register_options(
      [
        OptAddress.new('SRVHOST',   [ true, "The local host to listen on.", '0.0.0.0' ]),
        OptPort.new('SRVPORT',      [ true, "The local port to listen on.", 69 ]),
        OptPath.new('TFTPROOT',   [ true, "The TFTP root directory to serve files from", Dir.tmpdir  ]),
        OptPath.new('OUTPUTPATH', [ true, "The directory in which uploaded files will be written.", Dir.tmpdir ])
      ], self.class)
  end

  def srvhost
    datastore['SRVHOST'] || '0.0.0.0'
  end

  def srvport
    datastore['SRVPORT'] || 69
  end

  def run
    print_status("Starting TFTP server on #{srvhost}:#{srvport}...")

    @tftp = Rex::Proto::TFTP::Server.new(
      srvport,
      srvhost,
      {}
    )

    @tftp.set_tftproot(datastore['TFTPROOT'])
    print_status("Files will be served from #{datastore['TFTPROOT']}")

    @tftp.set_output_dir(datastore['OUTPUTPATH'])
    print_status("Uploaded files will be saved in #{datastore['OUTPUTPATH']}")

    # Individual virtual files can be served here -
    #@tftp.register_file("ays", "A" * 2048) # multiple of 512 on purpose

    @tftp.start
    add_socket(@tftp.sock)

    # Wait for finish..
    while @tftp.thread.alive?
      sleep 3
    end

    vprint_status("Stopping TFTP server")
    @tftp.stop
  end

end
