# This Module will act as an intermediate between metasploit console and meterpreter WebConsole.
# it will initiate WebConsole server for a specific session. Glue code present in this Class will
# fetch lists of post module from msfconsole in json format and will be converted in a format that can
# be readable by the browser.

require 'rex/ui/text/output/stdio'
require './tools/session-ui/backend'
require 'sinatra-websocket'
require 'eventmachine'
require 'sinatra/base'

def run_app(opts)

  EM.run do
    server  = opts[:server] || 'thin'
    host    = opts[:host]   || '0.0.0.0'
    port    = opts[:port]   || '8181'
    web_app = opts[:app]

    dispatch = Rack::Builder.app do
      map '/' do
        run web_app
      end
    end

    unless ['thin', 'hatetepe', 'goliath'].include? server
      raise "Need an EM webserver, but #{server} isn't"
    end

    Rack::Server.start({
                           app:    dispatch,
                           server: server,
                           Host:   host,
                           Port:   port,
                           signals: false,
                       })
  end
end

class WebConsoleServer < Sinatra::Base
  configure do
    set :threaded, true
    set :connections, []
    set :content_type, 'json'
    set :json_content_type, :js
    set :clients, []
  end
##
# TODO: Check if the session is running, it not then clise all the web socket instance and notify the user about the same.
# Enable session in sinatra app, to store history of command for every single user
##
  get('/') do
        if !request.websocket?
          File.open(File.join(File.dirname(__FILE__) + '/public', 'public.html'))
        else
          request.websocket do |ws|
            ws.onopen do
              ws.send("Welcome to Meterpreter Web socket,Connection Established!".to_json)
              settings.connections << ws
            end

            ws.onmessage do |msg|
              EM.next_tick do
                ws.send("\n" + ServerMethods.execute_script(msg))
              end
            end

            ws.onclose do
              warn("WebSocket Closed! ")
              settings.connections.delete(ws);
            end

          end

        end
      end

      get "/sysinfo" do
        ServerMethods.session_info
      end

      get"/modal" do
        content_type :json
        script = params[:script]
        ServerMethods.postmodule_info(script)
      end

      get "/modal2" do
        content_type :json
        command = params[:command]
        ServerMethods.extension_help(command)
      end

      get "/post" do
        content_type :json
        ServerMethods.get_post
      end

      get "/exten" do
        content_type :json
        ServerMethods.extension
      end
      # For invalid command
      not_found do
        "Whoops! You requested a route that wasn't available"
      end

end

