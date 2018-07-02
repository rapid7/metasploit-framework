require "sinatra/base"
require "sinatra/json"
require "json"

# This Class will act as an intermediate between metasploit console and meterpreter WebConsole.
# it will initiate WebConsole server for a specific session. Glue code present in this Class will
# fetch lists of post module from msfconsole in json format and will be converted in a format that can
# be readable by the browser.




module Msf

module Intermediate

  class Server < Sinatra::Base

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
    post "/run_post" do
      return "Post Exploitation Module entered is "
    end

    post "/run_exten" do
      return "Extension Commands Entered by user is #{params[:exten_cmd]}"
    end
  run!
  end

  class Getdata
    def initialize

    end
    # instantiate and run the server
    def start_server
      server=Server.new
      server.run!
    end

    def get_post
      # Fetch list of all available post exploitation module
    end

    def get_exten
      # Fetch List of extension commands available on an active session
    end

    def post_info
      # This method will use msf/base/serializer/json Class to dump information for
      # post modules. dump_post_module(mod)
    end

    def sys_info
      # Fetch system information of the victim's machine.
    end
  end
# This class will return the desired output of requests received from the WebConsole.
# It will execute post Exploitation Module and executes extension commands, and return
# the output in json format.

  class CmdExecute
    def initialize

    end

    def run_post
    # run Post Exploitation module commands and return the output in json format
    end

    def run_exten
    #run Extension commands
    end

  end


  class Xterm_session
    # This class will execute web socket and provide Session connectivity with Meterpreter shell and Xterm
    # Read each command, validates it, filters it and then sends it to shell
    # While this period of time, The communication will remain persistence.
    #
  end

end
end

s=Intermediate::Server.new
s.start_server




=begin
while sid && method== 'web_ui'
        session = verify_session(sid)
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end
          print_status("Starting interaction with #{session.name}...\n") unless quiet
          begin
            self.active_session = session
            sid = session.interact(driver.input.dup, driver.output)
            self.active_session = nil
            driver.input.reset_tab_completion if driver.input.supports_readline
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
        else
          sid = nil
        end
      end
=end
