##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Rex::Proto::TFTP
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'TFTP File Transfer Utility',
      'Description' => %q{
          This module will transfer a file to or from a remote TFTP server.
          Note that the target must be able to connect back to the Metasploit system,
          and NAT traversal for TFTP is often unsupported.

          Two actions are supported: "Upload" and "Download," which behave as one might
          expect -- use 'set action Actionname' to use either mode of operation.

          If "Download" is selected, at least one of FILENAME or REMOTE_FILENAME
          must be set. If "Upload" is selected, either FILENAME must be set to a valid path to
          a source file, or FILEDATA must be populated. FILENAME may be a fully qualified path,
          or the name of a file in the Msf::Config.local_directory or Msf::Config.data_directory.
        },
      'Author'      => [ 'todb' ],
      'References'  =>
        [
          ['URL', 'http://www.faqs.org/rfcs/rfc1350.html'],
          ['URL', 'http://www.networksorcery.com/enp/protocol/tftp.htm']
        ],
      'Actions' => [
        [ 'Download', {'Description' => "Download REMOTE_FILENAME as FILENAME from the server."}],
        [ 'Upload',   {'Description' => "Upload FILENAME as REMOTE_FILENAME to the server."}]
        ],
      'DefaultAction' => 'Upload',
      'License'     => MSF_LICENSE
    )
    register_options([
      OptString.new( 'FILENAME', [false, "The local filename" ]),
      OptString.new( 'FILEDATA', [false, "Data to upload in lieu of a real local file." ]),
      OptString.new( 'REMOTE_FILENAME', [false, "The remote filename"]),
      OptAddress.new('RHOST',    [true, "The remote TFTP server"]),
      OptPort.new(   'LPORT',    [false, "The local port the TFTP client should listen on (default is random)" ]),
      OptAddress.new('LHOST',    [false, "The local address the TFTP client should bind to"]),
      OptString.new( 'MODE',     [false, "The TFTP mode; usual choices are netascii and octet.", "octet"]),
      Opt::RPORT(69)
    ], self.class)
  end

  def mode
    datastore['MODE'] || "octect"
  end

  def remote_file
    return datastore['REMOTE_FILENAME'] if datastore['REMOTE_FILENAME']
    return ::File.split(datastore['FILENAME']).last if datastore['FILENAME']
  end

  def rport
    datastore['RPORT'] || 69
  end

  def rhost
    datastore['RHOST']
  end

  # Used only to store loot, doesn't actually have any semantic meaning
  # for the TFTP protocol.
  def datatype
    case datastore['MODE']
    when "netascii"
      "text/plain"
    else
      "application/octet-stream"
    end
  end

  def file
    if action.name == "Upload"
      fdata = datastore['FILEDATA'].to_s
      fname = datastore['FILENAME'].to_s
      if not fdata.empty?
        fdata_decorated = "DATA:#{datastore['FILEDATA']}"
      elsif ::File.readable? fname
        fname
      else
        fname_local = ::File.join(Msf::Config.local_directory,fname)
        fname_data  = ::File.join(Msf::Config.data_directory,fname)
        return fname_local if ::File.file?(fname_local) and ::File.readable?(fname_local)
        return fname_data  if ::File.file?(fname_data)  and ::File.readable?(fname_data)
        return nil # Couldn't find it, giving up.
      end
    else # "Download"
      fname = ::File.split(datastore['FILENAME'] || datastore['REMOTE_FILENAME']).last rescue nil
    end
  end

  # Experimental message prepending thinger. Might make it up into the
  # standard Metasploit lib like vprint_status and friends.
  def rtarget(ip=nil)
    if (ip or rhost) and rport
      [(ip || rhost),rport].map {|x| x.to_s}.join(":") << " "
    elsif (ip or rhost)
      "#{rhost} "
    else
      ""
    end
  end

  # This all happens before run(), and should give an idea on how to use
  # the TFTP client mixin. Essentially, you create an instance of the
  # Rex::Proto::TFTP::Client class, fill it up with the relevant host and
  # file data, set it to either :upload or :download, then kick off the
  # transfer as you like.
  def setup
    @lport = datastore['LPORT'] || (1025 + rand(0xffff-1025))
    @lhost = datastore['LHOST'] || "0.0.0.0"
    @local_file = file
    @remote_file = remote_file

    @tftp_client = Rex::Proto::TFTP::Client.new(
      "LocalHost"  => @lhost,
      "LocalPort"  => @lport,
      "PeerHost"   => rhost,
      "PeerPort"   => rport,
      "LocalFile"  => @local_file,
      "RemoteFile" => @remote_file,
      "Mode"       => mode,
      "Context"    => {'Msf' => self.framework, 'MsfExploit' => self},
      "Action"     => action.name.to_s.downcase.intern
    )
  end

  def run
    case action.name
    when 'Upload'
      if file
        run_upload()
      else
        print_error "Need at least a local file name or file data to upload."
        return
      end
    when 'Download'
      if remote_file
        run_download()
      else
        print_error "Need at least a remote file name to download."
        return
      end
    else
      print_error "Unknown action: '#{action.name}'"
    end
    while not @tftp_client.complete
      select(nil,nil,nil,1)
      print_status [rtarget,"TFTP transfer operation complete."].join
      save_downloaded_file() if action.name == 'Download'
      break
    end
  end

  # Run in case something untoward happend with the connection and the
  # client object didn't get stopped on its own. This can happen with
  # transfers that got interrupted or malformed (like sending a 0 byte
  # file).
  def cleanup
    if @tftp_client and @tftp_client.respond_to? :complete
      while not @tftp_client.complete
        select(nil,nil,nil,1)
        vprint_status "Cleaning up the TFTP client ports and threads."
        @tftp_client.stop
      end
    end
  end

  def run_upload
    print_status "Sending '#{file}' to #{rhost}:#{rport} as '#{remote_file}'"
    ret = @tftp_client.send_write_request { |msg| print_tftp_status(msg) }
  end

  def run_download
    print_status "Receiving '#{remote_file}' from #{rhost}:#{rport} as '#{file}'"
    ret = @tftp_client.send_read_request { |msg| print_tftp_status(msg) }
  end

  def save_downloaded_file
    print_status "Saving #{remote_file} as '#{file}'"
    fh = @tftp_client.recv_tempfile
    data = File.open(fh,"rb") {|f| f.read f.stat.size} rescue nil
    if data and not data.empty?
      unless framework.db.active
        print_status "No database connected, so not actually saving the data:"
        print_line data
      end
      this_service = report_service(
        :host => rhost,
        :port => rport,
        :name => "tftp",
        :proto => "udp"
      )
      store_loot("tftp.file",datatype,rhost,data,file,remote_file,this_service)
    else
      print_status [rtarget,"Did not find any data, so nothing to save."].join
    end
    fh.unlink rescue nil # Windows often complains about unlinking tempfiles
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

end
