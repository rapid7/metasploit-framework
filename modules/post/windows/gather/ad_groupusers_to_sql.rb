##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'
require 'sqlite3'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP
  include Msf::Post::Windows::Accounts

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'AD Group & User Membership to Offline SQL Database',
      'Description'  => %{
        This module will gather a list of AD groups, identify the users (taking into account recursion)
        and optionally write this to a greppable file, a SQLite database or a mysql-compatible SQL file
        for offline analysis.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))
  end

  # Entry point
  def run
    max_search = datastore['MAX_SEARCH']

    db, dbfile = create_sqlite_db
    print_status "Database created: #{dbfile.to_s}"

    # Download the list of groups from Active Directory
    vprint_status "Retrieving AD Groups"
    begin
      group_filter = '(objectClass=group)'
      group_fields = ['distinguishedName','objectSid','samAccountType','sAMAccountName','whenChanged','whenCreated','description']
      groups = query(group_filter, max_search, group_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error("Error(Group): #{e.message.to_s}")
      return
    end

    # If no groups were downloaded, there's no point carrying on
    if groups.nil? || groups[:results].empty?
      print_error('No AD groups were discovered')
      return
    end

    # Go through each of the groups and identify the individual users in each group
    vprint_status "Retrieving AD Group Membership"
    users_fields = ['distinguishedName','objectSid','sAMAccountType','sAMAccountName','displayName','description','logonCount','userAccountControl','userPrincipalName','whenChanged','whenCreated']
    group_counter = 0
    groups[:results].each do |individual_group|
      begin

        # Perform the ADSI query to retrieve the effective users in each group (recursion)
        vprint_status "Retrieving members of #{individual_group[3][:value].to_s}"
        users_filter = "(&(objectCategory=person)(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=#{individual_group[0][:value].to_s}))"
        users_in_group = query(users_filter, max_search, users_fields)
        next if users_in_group.nil? || users_in_group[:results].empty?
        group_sid, group_rid = sid_hex_to_string(individual_group[1][:value])
     
        # Add the group to the database
        sql_param_group = { :rid => group_rid.to_i, 
                            :distinguishedName => individual_group[0][:value],
                            :sAMAccountName => individual_group[3][:value],
                            :description => individual_group[4][:value]
                          }
        db.execute("insert into ad_groups (rid, distinguishedName, sAMAccountName, description) VALUES (:rid,:distinguishedName,:sAMAccountName,:description)", sql_param_group)

        # Go through each of the users in the group
        users_in_group[:results].each do |group_user|
          user_sid, user_rid = sid_hex_to_string(group_user[1][:value])
          print_line "Group [#{individual_group[3][:value].to_s}][#{group_rid.to_s}] has member [#{group_user[3][:value].to_s}][#{user_rid.to_s}]"

          # Add the group to the database
          sql_param_user = { :rid => user_rid.to_i, 
                             :distinguishedName => group_user[0][:value],
                             :sAMAccountName => group_user[3][:value],
                             :description => group_user[5][:value]
                           }
          db.execute("replace into ad_users (rid, distinguishedName, sAMAccountName, description) VALUES (:rid,:distinguishedName,:sAMAccountName,:description)", sql_param_user)

          # Now associate the user with the group
          sql_param_mapping = { :user_rid => user_rid.to_i, 
                                :group_rid => group_rid.to_i
                              }
          db.execute("insert into ad_mapping (user_rid,group_rid) VALUES (:user_rid,:group_rid)", sql_param_mapping)

          group_counter += 1
        end
      rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
        print_error("Error(Users): #{e.message.to_s}")
        return
      end
    end

    print_status "Enumerated #{group_counter} group(s)"
  end

 # Creat the SQLite Database
 def create_sqlite_db
   begin
     filename = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('ad', 5)}.db"
     db = SQLite3::Database.new(filename)
     
     # Create the table for the AD Groups
     sql_table_group = 'CREATE TABLE ad_groups ('\
                          'rid INTEGER PRIMARY KEY NOT NULL,'\
                          'distinguishedName TEXT UNIQUE NOT NULL,'\
                          'sAMAccountName TEXT,'\
                          'description TEXT'\
                          'whenChanged TEXT,'\
                          'whenCreated TEXT)'
     db.execute(sql_table_group)

     # Create the table for the AD Users
     sql_table_users = 'CREATE TABLE ad_users ('\
                          'rid INTEGER PRIMARY KEY NOT NULL,'\
                          'distinguishedName TEXT UNIQUE NOT NULL,'\
                          'description TEXT,'\
                          'sAMAccountName TEXT,'\
                          'logonCount INTEGER,'\
                          'userPrincipalName TEXT,'\
                          'whenCreated TEXT,'\
                          'whenChanged TEXT)'
     db.execute(sql_table_users)

     # Create the table for the mapping between the two (membership)
     sql_table_mapping = 'CREATE TABLE ad_mapping ('\
                          'user_rid INTEGER NOT NULL,' \
                          'group_rid INTEGER NOT NULL,'\
                          'PRIMARY KEY (user_rid, group_rid))'
     db.execute(sql_table_mapping)

     return db, filename
   rescue SQLite3::Exception => e
     print_error("Error(Database): #{e.message.to_s}")
     return
   end
 end

 # Convert the SID raw data to a string. TODO fix this mess....
 # THIS NEEDS FIXING FIXME FIXME
 def sid_hex_to_string(data)
   sid = []
   sid << data[0].to_s
   rid = ''
   (6).downto(1) do |i|
     rid += byte2hex(data[i, 1][0])
   end
   sid << rid.to_i.to_s
   sid += data.unpack("bbbbbbbbV*")[8..-1]
   final_sid = "S-" + sid.join('-')
   return final_sid, sid[-1]
 end
 def byte2hex(b)
   ret = '%x' % (b.to_i & 0xff)
   ret = '0' + ret if ret.length < 2
   ret
 end
end 
