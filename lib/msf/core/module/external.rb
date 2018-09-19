require 'msf/core/modules/external'

module Msf::Module::External
  include Msf::Auxiliary::Report
  include Msf::Module::Auth

  def execute_module(path, method: :run, args: datastore, fail_on_exit: true)
    mod = Msf::Modules::External.new(path, framework: framework)
    success = mod.exec(method: method, args: args) do |m|
      begin
        case m.method
        when :message
          log_output(m)
        when :report
          process_report(m, mod)
        when :reply
          return m.params['return']
        end
      rescue Interrupt => e
        raise e
      rescue Exception => e
        elog e.backtrace.join("\n")
        fail_with Msf::Module::Failure::Unknown, e.message
      end
    end

    fail_with Msf::Module::Failure::Unknown, "Module exited abnormally" if fail_on_exit && !success
  end

  def log_output(m)
    message = m.params['message']

    case m.params['level']
    when 'error'
      print_error message
    when 'warning'
      print_warning message
    when 'good'
      print_good message
    when 'info'
      print_status message
    when 'debug'
      vprint_status message
    else
      print_status message
    end
  end

  def process_report(m, mod)
    data = m.params['data']

    case m.params['type']
    when 'host'
      # Required
      host = {host: data['host']}

      # Optional
      host[:state] = data['state'] if data['state'] # TODO: validate -- one of the Msf::HostState constants (unknown, alive, dead)
      host[:os_name] = data['os_name'] if data['os_name']
      host[:os_flavor] = data['os_flavor'] if data['os_flavor']
      host[:os_sp] = data['os_sp'] if data['os_sp']
      host[:os_lang] = data['os_lang'] if data['os_lang']
      host[:arch] = data['arch'] if data['arch'] # TODO: validate -- one of the ARCH_* constants
      host[:mac] = data['mac'] if data['mac']
      host[:scope] = data['scope'] if data['scope']
      host[:virtual_host] = data['virtual_host'] if data['virtual_host']

      report_host(host)
    when 'service'
      # Required
      service = {host: data['host'], port: data['port'], proto: data['proto']}

      # Optional
      service[:name] = data['name'] || mod.meta['service_name'] if data['name'] || mod.meta['service_name']

      report_service(service)
    when 'vuln'
      # Required
      vuln = {host: data['host'], name: data['name']}

      # Optional
      vuln[:info] = data['info'] if data['info']
      vuln[:refs] = data['refs'] if data['refs']
      vuln[:port] = data['port'] if data['port']
      vuln[:proto] = data['port'] if data['port']

      # Metasploit magic
      vuln[:refs] = self.references

      report_vuln(vuln)
    when 'correct_password'
      # Required
      cred = {user: data['username'], private: data['password']}

      # Optional
      cred[:proof] = data['proof'] if data['proof']
      cred[:service_data] =
        {
          origin_type: :service,
          protocol: data['protocol'] || 'tcp',
          service_name: data['service_name'] || mod.meta['service_name'],
          address: data['host'] || datastore['rhost'] || rhost,
          port: data['port'] || datastore['rport'] || rport
        }

      cred[:private_type] = :password

      store_valid_credential(**cred)
    when 'wrong_password'
      # Required
      cred = {public: data['username'], private: data['password']}

      # Optional
      cred.merge!({
        address: data['host'] || datastore['rhost'] || rhost,
        port: data['port'] || datastore['rport'] || rport,
        protocol: data['protocol'] || 'tcp',
        status: Metasploit::Model::Login::Status::INCORRECT
      })

      invalidate_login(**cred)
    else
      print_warning "Skipping unrecognized report type #{m.params['type']}"
    end
  end
end
