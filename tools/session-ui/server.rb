<<<<<<< HEAD
require "sinatra/base"
require "sinatra/json"
require "json"
=======
require "sinatra"
<<<<<<< HEAD
require "json"
require "sinatra/json"
=======
require "sinatra/json"
require "json"
require "sinatra/base"
require "sinatra-websocket"
>>>>>>> 91fd371df83cc71561aceb9b98944b876edf650f

=begin
msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']
>>>>>>> 5925662643f991a2ad267b2ad7dbbbbd02e46a9a


<<<<<<< HEAD
configure do


  set :bind, '127.0.0.1'
  set :port, 3000
  set :json_content_type, :js
  set :public_folder, 'public'

end
  get "/" do
    File.read(File.join('public','public.html'))
  end
=======

<<<<<<< HEAD
class Server < Sinatra::Base
=======
set :bind, '127.0.0.1'
set :port, 3000
set :json_content_type, :js
set :public_folder, 'public'

>>>>>>> 91fd371df83cc71561aceb9b98944b876edf650f
>>>>>>> 5925662643f991a2ad267b2ad7dbbbbd02e46a9a

configure do
  set :bind, '127.0.0.1'
  set :port, 3000
  set :json_content_type, :js
  set :public_folder, 'public'
end

get '/' do
  # receives an input from
  File.read(File.join('public','public.html'))
end

get "/sysinfo" do
  content_type :json
  system_info=File.read('sysinfo.json')
  return(system_info)
end
#To load Post Exploitation Module

post "/modal" do
  content_type :json
end

get "/post" do
  content_type :json
  post_file=File.read('json_post.json')
  return(post_file)
end
#load Extension command
get "/exten" do
  content_type :json
  exten_file=File.read('exten.json')
  return(exten_file)
end
# For invalid command
not_found do
  "Whoops! You requested a route that wasn't available"
end
#Get System information
<<<<<<< HEAD
post "/run_post" do
=======


<<<<<<< HEAD
  post "/post_command" do
    return "Post Exploitation Module entered is "
  end

  post "/exten_command?id=:exten_cmd" do
    return "Extension Commands Entered by user is #{params[:exten_cmd]}"
  end

=======
post "/post_command" do
>>>>>>> 5925662643f991a2ad267b2ad7dbbbbd02e46a9a
  return "Post Exploitation Module entered is "
end
>>>>>>> 91fd371df83cc71561aceb9b98944b876edf650f

post "/run_exten" do
  return "Extension Commands Entered by user is #{params[:exten_cmd]}"
end
  run!
end


=begin
# Web terminal Implementation

=begin
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
=end