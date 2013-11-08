<ruby>
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

#
# Put your 'require' here
#

#
# RC files currently have no 'modinfo' like a real Metasploit module, so this help message
# will have to do the trick for now.
#
def help
  msg = %Q|
  Description:
    Let's describe what this RC script is all about, plus anything the user should know before
    actually using it.

  Usage:
    msfconsole -r <rc file> <db_user> <db_pass> <db_workspace> <arg1>

  Options:
    <rc file>      - I'm sure you already know
    <db_user>      - Username for the database  (datastore: 'DB_USER')
    <db_pass>      - Password for the database  (datastore: 'DB_PASS')
    <db_workspace> - Workspace for the database (datastore: 'DB_WORKSPACE')
    <arg1>         - Argument 1                 (datastore: 'ARG1')

  Authors:
    sinn3r <sinn3r[at]metasploit.com>
  |

  msg = msg.gsub(/^\t/, '')
  print_line(msg)
end


#
# See if we're already connected
#
def is_db_active?
  begin
    framework.db.hosts
    return true
  rescue ::ActiveRecord::ConnectionNotEstablished
    return false
  end
end


#
# Initialize the database.
# Default to localhost:5432, as this is the default configuration suggested by the manual.
#
def init_db(username, password, workspace)
  db = "localhost:5432"
  print_status("Opening #{workspace} at #{db}")
  run_single("db_connect #{username}:#{password}@#{db}/#{workspace}")
end


#
# Initialize the argumets here
#
def init_args
  args = {}

  joint = ARGV.join('')
  if joint =~ /^help$/i
    args[:help] = true
    return args
  end

  # Add more arguments according to your help() function
  datastore = framework.datastore
  args[:db_user]      = ARGV.shift || datastore['DB_USER'] || ''
  args[:db_pass]      = ARGV.shift || datastore['DB_PASS'] || ''
  args[:db_workspace] = ARGV.shift || datastore['DB_WORKSPACE'] || ''
  args[:arg1]         = ARGV.shift || datastore['ARG1'] || ''

  if not is_db_active?
    if args[:db_user].empty? or args[:db_pass].empty? or args[:db_workspace].empty?
      raise ArgumentError, "Need DB_USER, DB_PASS, and DB_WORKSPACE"
    end
  end

  raise ArgumentError, "Need ARG1" if args[:arg1].empty?

  return args
end


#
# This is your main function
#
def main(args)
  print_status("Initialzation is done, and here's your input: #{args[:arg1]}")
end


#
# Below initializes the arguments and database
#
begin
  args = init_args
  if args[:help]
    help
    return
  end

  init_db(args[:db_user], args[:db_pass], args[:db_workspace]) if not is_db_active?
  main(args)

rescue ArgumentError => e
  print_error("Bad argument(s): #{e.message}")
  return

rescue RuntimeError => e
  # Any runtime error should be raised as "RuntimeError"
  print_error(e.message)
  return

rescue ::Exception => e
  # Whatever unknown exception occurs, we raise it
  raise e
end

</ruby>