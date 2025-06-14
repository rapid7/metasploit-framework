##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanFile
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Backup File Scanner',
      'Description'	=> %q{
        This module identifies the existence of possible copies
        of a specific file in a given path.
      },
      'Author' 		=> [ 'et [at] cyberspace.org' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path/file to identify backups", '/index.asp'])
      ])

  end

  def run_host(ip)
    bakextensions = [
      '.backup',
      '.bak',
      '.copy',
      '.copia',
      '.old',
      '.orig',
      '.temp',
      '.txt',
      '~'
    ]

    bakextensions.each do |ext|
      file = normalize_uri(datastore['PATH'])+ext
      check_for_file(file, ip)
    end
    if datastore['PATH'] =~ %r#(.*)(/.+$)#
      file = $1 + $2.sub('/', '/.') + '.swp'
      check_for_file(file, ip)
    end
  end
  def check_for_file(file, ip)
    begin
      res = send_request_cgi({
          'uri'  		=>  file,
          'method'   	=> 'GET',
          'ctype'		=> 'text/plain'
          }, 20)

      if (res and res.code >= 200 and res.code < 300)
        print_good("Found #{wmap_base_url}#{file}")

        report_web_vuln(
          :host	=> ip,
          :port	=> rport,
          :vhost  => vhost,
          :ssl    => ssl,
          :path	=> file,
          :method => 'GET',
          :pname  => "",
          :proof  => "Res code: #{res.code.to_s}",
          :risk   => 0,
          :confidence   => 100,
          :category     => 'file',
          :description  => 'Backup file found.',
          :name   => 'backup file'
        )

      else
        vprint_status("NOT Found #{wmap_base_url}#{file}")
        #To be removed or just displayed with verbose debugging.
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end


  end
end
