require 'rack/lobster'

class Benchmarker
  PORT    = 7000
  ADDRESS = '0.0.0.0'
  
  attr_accessor :requests, :concurrencies, :servers, :keep_alive
  
  def initialize
    @servers = %w(Mongrel EMongrel Thin)
    @requests = 1000
    @concurrencies = [1, 10, 100]
  end
  
  def writer(&block)
    @writer = block
  end
  
  def run!
    @concurrencies.each do |concurrency|
      @servers.each do |server|
        req_sec, failed = run_one(server, concurrency)
        @writer.call(server, @requests, concurrency, req_sec, failed)
      end
    end
  end
  
  private
    def start_server(handler_name)
      @server = fork do
        [STDOUT, STDERR].each { |o| o.reopen "/dev/null" }

        case handler_name
        when 'EMongrel'
          require 'swiftcore/evented_mongrel'
          handler_name = 'Mongrel'
        end

        app = proc do |env|
          [200, {'Content-Type' => 'text/html', 'Content-Length' => '11'}, ['hello world']]
        end

        handler = Rack::Handler.const_get(handler_name)
        handler.run app, :Host => ADDRESS, :Port => PORT
      end
    
      sleep 2
    end
  
    def stop_server
      Process.kill('SIGKILL', @server)
      Process.wait
    end
  
    def run_ab(concurrency)
      `nice -n20 ab -c #{concurrency} -n #{@requests} #{@keep_alive ? '-k' : ''} #{ADDRESS}:#{PORT}/ 2> /dev/null`
    end
  
    def run_one(handler_name, concurrency)
      start_server(handler_name)

      out = run_ab(concurrency)

      stop_server

      req_sec = if matches = out.match(/^Requests.+?(\d+\.\d+)/)
        matches[1].to_i
      else
        0
      end
    
      failed = if matches = out.match(/^Failed requests.+?(\d+)/)
        matches[1].to_i
      else
        0
      end
    
      [req_sec, failed]
    end
end