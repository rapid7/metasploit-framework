##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/rpc/v10/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Metasploit RPC Interface Login Utility',
      'Description'   => %q{
        This module simply attempts to login to a
        Metasploit RPC interface using a specific
        user/pass.
      },
      'Author'        => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'       => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(55553),
        OptString.new('USERNAME', [true, "A specific username to authenticate as. Default is msf", "msf"]),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false]),
        OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
      ])

    register_autofilter_ports([3790])
  end

  def run_host(ip)
    begin
      @rpc = Msf::RPC::Client.new(
        :host => rhost,
        :port => rport,
        :ssl  => ssl
      )
    rescue ::Interrupt
      raise $!
    rescue => e
      vprint_error("Cannot create RPC client : #{e}")
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

  def do_login(user = 'msf', pass = 'msf')
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    begin
      res = @rpc.login(user, pass)
      if res
        print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")
        report_cred(
          ip: rhost,
          port: rport,
          service_name: 'msf-rpc',
          user: user,
          password: pass
        )
        return :next_user
      end
    rescue Rex::ConnectionRefused => e
      print_error("Connection refused : #{e}")
      return :abort
    rescue => e
      vprint_status("#{peer} - Bad login")
      return :skip_pass
    end
  ensure
    @rpc.close
  end
end
