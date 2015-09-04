##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP Git Scanner',
      'Description' => 'Detect git directories and files and analize its content.',
      'Author'       => ['t0nyhj'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to .git directory", '/'])

      ], self.class)

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true, "Error code for non existent directory", 404]),
        OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
            File.join(Msf::Config.data_directory, "wmap", "wmap_404s.txt")
          ]
        )

      ], self.class)
  end

  def run_host(target_host)
    conn = true
    ecode = nil
    emesg = nil

    tpath = normalize_uri(datastore['PATH'])

    ecode = datastore['ErrorCode']
    vhost = datastore['VHOST'] || wmap_target_host

    #
    # Detect error code
    #
    begin
      randdir = Rex::Text.rand_text_alpha(5).chomp + '/'
      res = send_request_cgi({
        'uri'  		=>  tpath+randdir,
        'method'   	=> 'GET',
        'ctype'		=> 'text/html'
      })

      return if not res

      tcode = res.code.to_i

      # Look for a string we can signature on as well
      if(tcode >= 200 and tcode <= 299)

        File.open(datastore['HTTP404Sigs'], 'rb').each do |str|
          if(res.body.index(str))
            emesg = str
            break
          end
        end

        if(not emesg)
          if datastore['VERBOSE']
          vprint_status :level => :verror, :ip => ip, :msg => "['#{target_host}'] Using first 256 bytes of the response as 404 string '#{res.code}'"
        end
          emesg = res.body[0,256]
        else
          if datastore['VERBOSE']
          vprint_status :level => :verror, :ip => ip, :msg => "['#{target_host}'] Using custom 404 string of '#{emesg}'"
        end
        end
      else
        ecode = tcode
        if datastore['VERBOSE']
          vprint_status :level => :verror, :ip => ip, :msg => "['#{target_host}'] Using code '#{ecode}' as not found."
        end
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      conn = false
    rescue ::Timeout::Error, ::Errno::EPIPE
      conn = false
    end

    return if not conn

    begin
      res = send_request_cgi({
        'uri'          => normalize_uri(tpath,'.git','config'),
        'method'       => 'GET',
        'version'      => '1.0',
      })

      unless res
        vprint_error("#{target_host} no response")
        return 
      end

      if(((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
        if datastore['VERBOSE']
          vprint_status :level => :verror, :ip => ip, :msg => "['#{target_host}'] NOT Found. '#{tpath}' '#{res.code}'"
        end
      else
        if (res.body.include?('core') or res.body.include?('remote') or res.body.include?('branch'))
          print_good("[#{target_host}:#{rport}] Git Config file found.")
        end
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end