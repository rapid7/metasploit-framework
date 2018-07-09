
# This Class will act as an intermediate between metasploit console and meterpreter WebConsole.
# it will initiate WebConsole server for a specific session. Glue code present in this Class will
# fetch lists of post module from msfconsole in json format and will be converted in a format that can
# be readable by the browser.
require './webconsoleServer'
require 'json'

class Backend

  @framework=nil
  @session_id=nil

  def initialize(framework_obj,sid)
    @framework = framework_obj
    @session_id=sid
  end

  def server_start(host,port)
    WebConsoleServer.run!(:port=>port,:host=>host)
  end

    def get_post()
      # Fetch list of all available post exploitation module. This method act as a glue code which will
      # format framework.post.keys output into desirable json format
      #
      # Still have minor bugs in parsing values into desired format
      # desired format is android/capture/screen {"android":{'capture":["screen"]}}
      #
      # Will be fixed in the next commit

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
              final.values[0].store(str[1],str[2])
            end
          else
            final[str[0]]=Hash[str[1],Array(str[2])]
          end
        end

      }
      puts final
    end

    def post_info(mod)
      # This method will use msf/base/serializer/json Class to dump information for
      # post modules. dump_post_module(mod)
      p_info=Msf::Serializer::Json.dump_post_module(mod)
      puts p_info
    end

    def sys_info
      # Fetch system information of the victim's machine.
      info= Msf::Serializer::ReadableText.dump_sessions_verbose(@framework)
      return info.to_json
    end
    def run_post_script(script)
      # run Post Exploitation module commands and return the output in json format

    end

    def run_exten_cmd
      #run Extension commands
    end
end

