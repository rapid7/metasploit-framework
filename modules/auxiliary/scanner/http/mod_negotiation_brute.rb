##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# mod_negotiation bruter
# http://httpd.apache.org/docs/1.3/content-negotiation.html
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'Apache HTTPD mod_negotiation Filename Bruter',
      'Description'	=> %q{
          This module performs a brute force attack in order to discover existing files on a
        server which uses mod_negotiation. If the filename is found, the IP address and the
        files found will be displayed.
      },
      'Author' 		=> [ 'diablohorn [at] gmail.com' ],
      'License'		=> MSF_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path to detect mod_negotiation", '/']),
        OptPath.new('FILEPATH',[true, "path to file with file names",
          File.join(Msf::Config.data_directory, "wmap", "wmap_files.txt")])
      ], self.class)
  end

  def run_host(ip)
    ecode = nil
    emesg = nil

    tpath = normalize_uri(datastore['PATH'])
    tfile = datastore['FILEPATH']

    if tpath[-1,1] != '/'
      tpath += '/'
    end

    #load the file with filenames into memory
    queue = []
    File.open(datastore['FILEPATH'], 'rb').each_line do |fn|
      queue << fn.strip
    end

    vhost = datastore['VHOST'] || ip
    prot  = datastore['SSL'] ? 'https' : 'http'

    #
    # Send the request and parse the response headers for an alternates header
    #
    begin
      queue.each do |dirname|
      reqpath = tpath+dirname
        # Send the request the accept header is key here
        res = send_request_cgi({
          'uri'  		=>  reqpath,
          'method'   	=> 'GET',
          'ctype'     => 'text/html',
          'headers'	=> {'Accept' => 'a/b'}
        }, 20)

        return if not res

        # Check for alternates header and parse them
        if(res.code == 406)
          chunks = res.headers.to_s.scan(/"(.*?)"/i).flatten
          chunks.each do |chunk|
            chunk = chunk.to_s
            print_status("#{ip} #{tpath}#{chunk}")
          end
        end
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end

  end
end
