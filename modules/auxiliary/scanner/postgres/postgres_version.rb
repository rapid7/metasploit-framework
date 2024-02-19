##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::PostgreSQL

  # Creates an instance of this module.
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PostgreSQL Version Probe',
      'Description'    => %q{
        Enumerates the version of PostgreSQL servers.
      },
      'Author'         => [ 'todb' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://www.postgresql.org/' ]
        ]
    ))

    register_options([ ]) # None needed.

    deregister_options('SQL', 'RETURN_ROWSET')
  end

  # Loops through each host in turn. Note the current IP address is both
  # ip and datastore['RHOST']
  def run_host(ip)
    self.postgres_conn = session.client if session
    user = datastore['USERNAME']
    pass = postgres_password
    do_fingerprint(user,pass,datastore['DATABASE'])
  end

  # Alias for RHOST
  def rhost
    datastore['RHOST']
  end

  # Alias for RPORT
  def rport
    datastore['RPORT']
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
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_fingerprint(user=nil,pass=nil,database=nil)
    begin
      msg = "#{rhost}:#{rport} Postgres -"
      password = pass || postgres_password
      vprint_status("#{msg} Trying username:'#{user}' with password:'#{password}' against #{rhost}:#{rport} on database '#{database}'") unless postgres_conn
      result = postgres_fingerprint(
        :db => database,
        :username => user,
        :password => password
      )
      if result[:auth]
        vprint_good "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Logged in to '#{database}' with '#{user}':'#{password}'" unless session
        print_status "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Version #{result[:auth]} (Post-Auth)"
      elsif result[:preauth]
        print_good "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Version #{result[:preauth]} (Pre-Auth)"
      else # It's something we don't know yet
        vprint_status "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Authentication Error Fingerprint: #{result[:unknown]}"
        print_status "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Version Unknown (Pre-Auth)"
      end

      # Reporting
      report_service(
        :host => postgres_conn.peerhost,
        :port => postgres_conn.peerport,
        :name => "postgres",
        :info => result.values.first
      )

      if self.postgres_conn
        report_cred(
          ip: postgres_conn.peerhost,
          port: postgres_conn.peerport,
          service_name: 'postgres',
          user: user,
          password: password,
          proof: "postgres_conn = #{self.postgres_conn.inspect}"
        )
      end

      if result[:unknown]
        report_note(
          :host => postgres_conn.peerhost,
          :proto => 'tcp',
          :sname => 'postgres',
          :port => postgres_conn.peerport,
          :ntype => 'postgresql.fingerprint',
          :data => "Unknown Pre-Auth fingerprint: #{result[:unknown]}"
        )
      end

      # Logout
      postgres_logout if self.postgres_conn && session.blank?

    rescue Rex::ConnectionError
      vprint_error "#{rhost}:#{rport} Connection Error: #{$!}"
      return :done
    end

  end
end
