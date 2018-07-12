# This Module will act as an intermediate between metasploit console and meterpreter WebConsole.
# it will initiate WebConsole server for a specific session. Glue code present in this Class will
# fetch lists of post module from msfconsole in json format and will be converted in a format that can
# be readable by the browser.

require 'sinatra/base'
require 'json'


module Server
  class WebConsoleServer < Sinatra::Base

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
      system_info=File.read(File.join(File.dirname(__FILE__),'sysinfo.json'))
      return system_info
    end

    post "/modal" do
      content_type :json

    end

    get "/post" do
      content_type :json
      post_file=File.read(File.join(File.dirname(__FILE__),'json_post.json'))
      return post_file
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

  class Back
    @framework=nil
    @session_id=nil

    def initialize(framework_obj,sid)
      @framework = framework_obj
      @session_id=sid
    end

    def get_post
      string = @framework.post.keys
      final=Hash.new
      string.each {|string|
        str=string.split('/')
        if str.length==2
          if final.include?(str[0])
            final[str[0]] =str[1]
          else
            final[str[0]]=Array[str[1]]
          end
        elsif str.length ==3
          if final.include?(str[0])
            if final.values[0].keys.include?(str[0][str[1]])
              final.values[0].keys == Array[str[2]]
            else
              final.values[0]=Hash[str[1],Array(str[2])]
            end
          else
            final[str[0]]=Hash[str[1],Array(str[2])]
          end
        end

      }
      return final.to_json
    end

    def sys_info
      # Fetch system information of the victim's machine.

      info= Msf::Serializer::ReadableText.dump_sessions_verbose(@framework)
      return info.to_json
    end

    def post_info(mod)
      # This method will use msf/base/serializer/json Class to dump information for
       post modules. dump_post_module(mod)
       p_info=Msf::Serializer::Json.dump_post_module(mod)
       puts p_info
    end

    def exten

    end

    def run_post_script(script)
      # run Post Exploitation module commands and return the output in json format

    end

    def run_exten_cmd
      #run Extension commands
    end

 end

end
