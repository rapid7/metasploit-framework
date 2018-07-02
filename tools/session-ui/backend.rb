require './server'

# This Class will act as an intermediate between metasploit console and meterpreter WebConsole.
# it will initiate WebConsole server for a specific session. Glue code present in this Class will
# fetch lists of post module from msfconsole in json format and will be converted in a format that can
# be readable by the browser.




module Msf

module Intermediate

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
s=Msf::Intermediate::Getdata.new
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
