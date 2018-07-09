require 'sinatra/base'
require 'json'

#require './backend'
class WebConsoleServer < Sinatra::Base

  configure :development do

    #set :root, File.dirname(__FILE__)
    set :json_content_type, :js
    set :public_folder, 'public'
    set :server, %w[thin mongrel webrick]

  end

  get '/' do
    # receives an input from
    puts " <h1>This is america! </h1>"
    File.open(File.join(File.dirname(__FILE__)+'/public','public.html'))
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
    post_file=File.open('json_post.json')
    return post_file


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
  post "/run_post" do
    puts "Post Exploitation Module entered is "
  end

  post "/run_exten" do
    puts "Extension Commands Entered by user is #{params[:exten_cmd]}"
  end

end
