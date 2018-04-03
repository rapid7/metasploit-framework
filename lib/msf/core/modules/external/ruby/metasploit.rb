require 'json'

module Metasploit
  class << self
    attr_accessor :logging_prefix

    def log(message, level: 'debug')
      rpc_send({
        jsonrpc: '2.0', method: 'message', params: {
          level: level,
          message: self.logging_prefix + message
        }
      })
    end

    def report_host(ip, **opts)
      report(:host, opts.merge(host: ip))
    end

    def report_service(ip, **opts)
      report(:service, opts.merge(host: ip))
    end

    def report_vuln(ip, name, **opts)
      report(:vuln, opts.merge(host: ip, name: name))
    end

    def run(metadata, callback)
      self.logging_prefix = ''
      req = JSON.parse($stdin.readpartial(10000), symbolize_names: true)
      if req[:method] == 'describe'
        rpc_send({
          jsonrpc: '2.0', id: req[:id], response: metadata
        })
      elsif req[:method] == 'run'
        callback.call req[:params]
        rpc_send({
          jsonrpc: '2.0', id: req[:id], response: {
            message: 'Module completed'
          }
        })
      end
    end

    def report(kind, data)
      rpc_send({
        jsonrpc: '2.0', method: 'report', params: {
          type: kind, data: data
        }
      })
    end

    def rpc_send(req)
      puts JSON.generate(req)
      $stdout.flush
    end
  end
end
