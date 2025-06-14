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

    def report_correct_password(username, password, **opts)
      report(:correct_password, opts.merge(username: username, password: password))
    end

    def report_wrong_password(username, password, **opts)
      report(:wrong_password, opts.merge(username: username, password: password))
    end

    def run(metadata, callback, soft_check: nil)
      self.logging_prefix = ''
      cb = nil
      req = JSON.parse($stdin.readpartial(10000), symbolize_names: true)
      if req[:method] == 'describe'
        capabilities = []
        capabilities << 'soft_check' if soft_check

        meta = metadata.merge(capabilities: capabilities)
        rpc_send({
          jsonrpc: '2.0', id: req[:id], result: meta
        })
      elsif req[:method] == 'soft_check'
        if soft_check
          cb = soft_check
        else
          rpc_send({
            jsonrpc: '2.0', id: req[:id], error: {code: -32601, message: 'Soft checks are not supported'}
          })
        end
      elsif req[:method] == 'run'
        cb = callback
      end

      if cb
        ret = cb.call req[:params]
        rpc_send({
          jsonrpc: '2.0', id: req[:id], result: {
            message: 'Module completed',
            'return' => ret
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
