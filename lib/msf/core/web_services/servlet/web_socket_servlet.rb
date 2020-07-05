require 'msf/core/rpc'
require 'faye/websocket'

module Msf::WebServices
  module WebsocketServlet
    Faye::WebSocket.load_adapter('thin')
    def self.api_path
      '/api/v1/websocket'
    end

    def self.api_path_for_notify
      "#{WebsocketServlet.api_path}/notify"
    end

    def self.api_path_for_console
      "#{WebsocketServlet.api_path}/console"
    end

    def self.registered(app)
      app.get WebsocketServlet.api_path_for_notify, &notify
      app.get WebsocketServlet.api_path_for_console, &console
    end

    def self.notify
      lambda {
        warden.authenticate!
        if Faye::WebSocket.websocket?(env)
          ws = Faye::WebSocket.new(env, nil, { ping: 15 })
          username = ws.env['warden'].authenticate ? ws.env['warden'].authenticate.username : nil
          ws.on :open do |_event|
            framework.websocket.register(:notify, ws)
            data = framework.websocket.wrap_websocket_data(:notify, 'login', { username: username })
            framework.websocket.notify(:notify, data)
          end

          ws.on :close do |_event|
            framework.websocket.deregister(:notify, ws)
            data = framework.websocket.wrap_websocket_data(:notify, 'logout', { username: username })
            framework.websocket.notify(:notify, data)
            ws = nil
          end

          ws.on :message do |event|
            begin
              ws_data = JSON.parse(event.data)
              framework.websocket.notify(:notify, ws_data.to_json)
            rescue JSON::ParserError => e
              data = framework.websocket.wrap_websocket_data(:notify, 'error', { error: e.to_s })
              ws.send(data)
            end
          end
          ws.rack_response
        else
          [200, { 'Content-Type' => 'application/json' }, ['Error']]
        end
      }
    end

    def self.console
      lambda {
        warden.authenticate!
        if Faye::WebSocket.websocket?(env)
          ws = Faye::WebSocket.new(env, nil, { ping: 15 })
          ws.on :open do |_event|
            framework.websocket.register(:console, ws)
            @console_driver = Msf::Ui::Web::Driver.new(framework: framework)
            @cid = @console_driver.create_console({})
            @console_driver.consoles[@cid].pipe.create_subscriber_proc(
              'ws', &proc { |output|
                       data = { cid: @cid, prompt: @console_driver.consoles[@cid].prompt, output: output }
                       ws.send(data.to_json)
                     }
            )
          end

          ws.on :close do |_event|
            framework.websocket.deregister(:console, ws)
            @console_driver.consoles[@cid].shutdown
            @console_driver.consoles.delete(@cid)
            ws = nil
          end

          ws.on :message do |event|
            input = event.data
            @console_driver.consoles[@cid].pipe.write_input(input)
          end
          ws.rack_response
        else
          [200, { 'Content-Type' => 'application/json' }, ['Error']]
        end
      }
    end
  end
end
