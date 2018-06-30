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

=end

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

set :bind, '127.0.0.1'
set :port, 3000
set :json_content_type, :js
set :public_folder, 'public'

>>>>>>> 91fd371df83cc71561aceb9b98944b876edf650f


get "/" do
  File.read(File.join('public','public.html'))
end

get "/sysinfo" do
  content_type :json
  system_info=File.read('sysinfo.json')
  return(system_info)

end

#To load Post Exploitation Module

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
  post "/post_command" do
    return "Post Exploitation Module entered is "
  end

  post "/exten_command?id=:exten_cmd" do
    return "Extension Commands Entered by user is #{params[:exten_cmd]}"
  end

=======
post "/post_command" do
  return "Post Exploitation Module entered is "
end
>>>>>>> 91fd371df83cc71561aceb9b98944b876edf650f

post "/exten_command?id=:exten_cmd" do
  return "Extension Commands Entered by user is #{params[:exten_cmd]}"
end


=begin
class Features



  # Extract List of Post Exploitation Modules in JSON Format
  # Extract list of Extension commands in JSON Format
  # Parse this data and embed it into ERB file

  post = File.read('json.txt')
  data= JSON.parse(post)




  def postmodlist
    # Extract the json output given by Meterpreter adn saves it into am array
    # send this array to erb file
    # dynamically create the views web page

    post=File.read('json_post.txt')
    data=JSON.pretty_generate(post)

  end



  def externlist
    #Extract the json output given by Meterpreter adn saves it into am array
    # send this array to erb file
    # dynamically create the views web page
    ext=File.read('json_ext.txt')
    data=JSON.pretty_generate(ext)
  end

  def sysinfo
    # parse sys info from json
    # send the data to erb file
    # to form dynamic web page content
    sys=File.read('json_ext.txt')
    data=JSON.pretty_generate(sys)

  end


end



class Xterm_session
  # This class will execute web socket and provide Session connectivity with Meterpreter shell and Xterm
  # Read each command, validates it, filters it and then sends it to shell
  # While this period of time, The communication will remain persistence.
  # Implementation of Web Socket is required he
end

#----------------------------------- To be Executed  before first Evaluation period -------------------------------------#


class Execute_Commands

  #execute meterpreter class methods
  # Take data from user and send it to Meterpreter shell.
  # Return the output back to the user
  # This class will handle commands related to Post Module and Extension send by AJAX
end
=end


# Web Socket Implementation

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
