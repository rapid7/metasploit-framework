# This Module will act as an intermediate between metasploit console and meterpreter WebConsole.
# it will initiate WebConsole server for a specific session. Glue code present in this Class will
# fetch lists of post module from msfconsole in json format and will be converted in a format that can
# be readable by the browser.
require 'socket'
require 'sinatra/base'
require 'json'
require 'sinatra-websocket'
require './tools/session-ui/backend'

  class WebConsoleServer < Sinatra::Base
    helpers Sinatra::Backend

    configure :development do
      set :json_content_type, :js
      set :public_folder, File.dirname(__FILE__)+'/public'
      set :server, %w[thin mongrel webrick]
      set :content_type,'json'
      set :sockets, []
    end


    get '/' do
      if !request.websocket?
        File.open(File.join(File.dirname(__FILE__)+'/public','public.html'))
      else
        request.websocket do |ws|
          ws.onopen do
            ws.send("Connection Established!")
            settings.sockets << ws
          end
          ws.onmessage do |msg|
            EM.next_tick {
              settings.sockets.each{|s|
                output=Sinatra::Backend::Server.execute_script(msg)
                s.send(output.to_json)
              }
            }
          end
          ws.onclose do
            ws.send("websocket closed")
            settings.sockets.delete(ws)
          end
        end
      end

    end

    get "/sysinfo" do
      Sinatra::Backend::Server.session_info
    end

    get"/modal" do
      content_type :json
      script=params[:script]
      Sinatra::Backend::Server.postmodule_info(script)
    end

    get "/modal2" do
      content_type :json
      command=params[:command]
      return Sinatra::Backend::Server.extension_help(command)
    end


    get "/post" do
      content_type :json
      Sinatra::Backend::Server.get_post
    end

    get "/exten" do
      content_type :json
      Sinatra::Backend::Server.extension
    end
    # For invalid command
    not_found do
      "Whoops! You requested a route that wasn't available"
    end

  end