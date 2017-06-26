require 'digest'
require 'rex/proto/arachni'

module Msf
class Plugin::Arachni < Msf::Plugin
  class ArachniCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      'Arachni'
    end

    def commands
      {
        'arachni_connect' => 'Connect to an Arachni RPC instance',
        'arachni_scan' => 'Scan a URL',
        'arachni_scanlog' => 'Get the log for the scan',
        'arachni_savelog' => 'Save the results of the scan to the database'
      }
    end

    def cmd_arachni_connect(*args)
      @dispatcher = Rex::Proto::Arachni::Client.new(
        host: args[0] || '127.0.0.1',
        port: args[1] ||7331
      )

      instance_info = @dispatcher.call('dispatcher.dispatch', Rex::Text.rand_text_alpha(8))
      @instance = Rex::Proto::Arachni::Client.new(
        host: args[0] || '127.0.0.1',
        port: instance_info['port'],
        token: instance_info['token']
      )
    end

    def cmd_arachni_scan(*args)
      unless @instance
        print_error("Please connect to your Arachni RPC instance with arachni_connect.")
        return
      end

      opts = {}
      opts['url'] = args[0]
      opts['checks'] = args[1] || '*'
      opts['audit'] = {}
      opts['audit']['elements'] = ['links', 'forms']

      @instance.call('service.scan', opts)

      @url = args[0]
    end

    def cmd_arachni_scanlog(*args)
      unless @instance
        print_error("Please connect to your Arachni RPC instance with arachni_connect.")
        return
      end

      log = @instance.call('service.progress', {"with": "issues"})
      status = @instance.call('service.busy?')

      i = 1
      log["issues"].each do |issue|
        print_good(i.to_s + ". " + issue["name"])
        i = i + 1
      end

      print_good("Scan running: " + status.to_s)
    end

    def cmd_arachni_savelog(*args)

      unless @instance
        print_error("Please connect to your Arachni RPC instance with arachni_connect.")
        return
      end

      unless @url
        print_error("Please start a scan against a web server before trying to save the results.")
        return
      end

      busy = @instance.call('service.busy?')

      unless !busy
        print_error("Please save the scan after it's finished running. Check the status with arachni_scanlog.")
        return
      end

      log = @instance.call('service.progress', {"with": "issues"})

      log["issues"].each do |issue|
        port = issue["vector"]["action"].split(':')[2]
        port = ((issue["vector"]["action"].split(':') == 'http') ? 80 : 443) unless port
        p port
        vuln_info = {}
        vuln_info[:web_site] = issue["vector"]["action"]
        vuln_info[:pname] = issue['vector']['affected_input_name']
        vuln_info[:method] = issue['vector']['method'].upcase
        vuln_info[:name] = issue['name']
        vuln_info[:category] = 'Arachni'
        vuln_info[:host] = issue["vector"]["action"].split('/')[2]
        vuln_info[:port] =  port
        vuln_info[:ssl] = issue["vector"]["action"].split(':') == 'http' ? false : true
        vuln_info[:risk] = 'Unknown'
        vuln_info[:path] = issue["vector"]["action"]
        vuln_info[:params] = issue['request']['parameters'].map{|k,v| [k,v]}
        vuln_info[:description] = issue['description']
        vuln_info[:proof] = issue['proof']
        p vuln_info
        framework.db.report_web_vuln(vuln_info)
      end
    end
  end

  def initialize(framework, opts)
    super
    print_status("Arachni plugin loaded.")
    add_console_dispatcher(ArachniCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('Arachni')
  end

  def name
    'Arachni'
  end

  def desc
    'Integrate Arachni with Metasploit'
  end
end
end
