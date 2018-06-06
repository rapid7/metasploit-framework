require "sinatra"
require "sinatra/json"
require "sinatra/cross_origin"
require "rubygems"
require "json"
require 'sinatra-websocket'

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']


set :bind, '127.0.0.1'
set :port, 3000

configure do
  enable :cross_origin
end

set :json_content_type, :js

#To load Post Exploitation Module 
get "/post" do
  return "I figured it out"
end

#To load Extension Commands
get "/extern" do
  return "Windows"
end

# Web Socket Implementation
get '/soc' do
    request.websocket do |ws|
      ws.onopen do
        ws.send("Hello World! How are you")
        settings.sockets << ws
      end
      ws.onmessage do |msg|
        EM.next_tick { settings.sockets.each{|s| s.send(msg) } }
      end
      ws.onclose do
        warn("websocket closed")
        settings.sockets.delete(ws)
      end
    end
end
