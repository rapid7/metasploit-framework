include Msf::Auxiliary::Report

module Msf::Module::External
  def wait_status(mod)
    while mod.running
      m = mod.get_status
      if m
        case m.method
        when :message
          log_output(m)
        when :report
          process_report(m)
        when :reply
          # we're done
          break
        end
      end
    end
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

  def process_report(m)
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
      service[:name] = data['name'] if data['name']

      report_service(service)
    else
      print_warning "Skipping unrecognized report type #{m.params['type']}"
    end
  end
end
