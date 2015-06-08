#
# $Id$
# $Revision$
#
module Msf

class Plugin::UserHunter < Msf::Plugin

  class SMBCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      "User Hunter"
    end

    def commands
      {
        'smb_hunt'        => "Search the database for specific user(s) found via smb enumeration"
      }
    end

    def cmd_print_usage(opts)
      print_line("Usage: smb_hunt [options] <username> [username] .. [username]")
      print_line(opts.usage)
      return
    end

    def cmd_verify_db
      if ! (framework.db and framework.db.usable and framework.db.active)
        print_error("No database has been configured, please use db_create/db_connect first")
        return false
      end

      true
    end

    def cmd_smb_hunt(*args)
      return if not cmd_verify_db

      opts = Rex::Parser::Arguments.new(
        "-h"   => [ false,  "This help menu"],
        "-v"   => [ false,  "Verbose flag"],
        "-f"   => [ true,   "A file containing a list of users to search for (one per line)"]
      )

      opt_userfile  = nil
      opt_users     = []
      opt_verbose   = false

      if(args.length == 0 or args[0].empty? or args[0] == "-h")
        cmd_print_usage(opts)
      end

      opts.parse(args) do |opt, idx, val|
        case opt
        when "-h"
          cmd_print_usage(opts)
        when "-f"
          opt_userfile = val
        when "-v"
          opt_verbose = true
        else
          opt_users << val
        end
      end

      if(opt_userfile)
        if ::File.readable?(opt_userfile)
          ::File.open(opt_userfile, "rb") do |fd|
            fd.each_line do |line|
              line.strip!
              next if line.empty?
              next if line =~ /^#/
              opt_users << line
            end
          end
        end
      end

      opt_users.uniq!

      framework.db.notes.each do |sid|
        if sid[:ntype] ==  'smb_loggedin_users'
          if opt_verbose
            print_status(">> Checking users from #{sid.host.address}")
          end
          if opt_users.include?(sid[:data][:user].to_s)
            print_good(">> FOUND USER: #{sid.host.address} - #{sid[:data][:user]}")
          end
        end
      end
    end
  end


  def initialize(framework, opts)
    super
    add_console_dispatcher(SMBCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('User Hunter')
  end

  def name
    "user_hunter"
  end

  def desc
    "Search for specific users"
  end
end
end
