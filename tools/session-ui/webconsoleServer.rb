# This Module will act as an intermediate between metasploit console and meterpreter WebConsole.
# it will initiate WebConsole server for a specific session. Glue code present in this Class will
# fetch lists of post module from msfconsole in json format and will be converted in a format that can
# be readable by the browser.

require 'sinatra/base'
require 'json'
require './tools/session-ui/backend'


  class WebConsoleServer < Sinatra::Base
    helpers Sinatra::Backend

    configure :development do
      #set :root, File.dirname(__FILE__)
      set :json_content_type, :js
      set :public_folder, File.dirname(__FILE__)+'/public'
      set :bind,'127.0.0.1'
      set :server, %w[thin mongrel webrick]
      set :content_type,'json'
    end


    get '/' do
      # receives an input from
      File.open(File.join(File.dirname(__FILE__)+'/public','public.html'))
    end


    get "/sysinfo" do
      #system_info=File.read(File.join(File.dirname(__FILE__),'sysinfo.json'))
      #return system_info
      return Sinatra::Backend::Server.sys_info
    end

    post "/modal" do
      content_type :json

    end

    get "/post" do
      content_type :json
      #post_file=File.read(File.join(File.dirname(__FILE__),'json_post.json'))
      #return post_file
      return Sinatra::Backend::Server.get_post
    end

    get '/postinfo' do
      content_type :json
      return Sinatra::Backend::Server.post_info('windows/gather/checkvm')
    end

    get "/exten" do
      content_type :json
      exten_file=File.read(File.join(File.dirname(__FILE__),'exten.json'))
      return exten_file
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
