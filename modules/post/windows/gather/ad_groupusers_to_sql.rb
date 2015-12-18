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
        and write this to a SQLite database for offline analysis and query using normal SQL syntax.
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
    users_fields = ['distinguishedName','objectSid','sAMAccountType','sAMAccountName','displayName','description','logonCount','userAccountControl','userPrincipalName','whenChanged','whenCreated','primaryGroupID','badPwdCount']
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
                            :distinguishedName => individual_group[0][:value].to_s,
                            :sAMAccountName => individual_group[3][:value].to_s,
                            :whenChanged => individual_group[4][:value].to_s,
                            :whenCreated => individual_group[5][:value].to_s,
                            :description => individual_group[6][:value].to_s
                          }
        run_sqlite_query(db, 'ad_groups',sql_param_group)

        # Go through each of the users in the group
        users_in_group[:results].each do |group_user|
          user_sid, user_rid = sid_hex_to_string(group_user[1][:value])
          print_line "Group [#{individual_group[3][:value].to_s}][#{group_rid.to_s}] has member [#{group_user[3][:value].to_s}][#{user_rid.to_s}]"

          # Add the group to the database
          sql_param_user = { :rid => user_rid.to_i, 
                             :distinguishedName => group_user[0][:value].to_s,
                             :sAMAccountName => group_user[3][:value].to_s,
                             :displayName => group_user[4][:value].to_s,
                             :description => group_user[5][:value].to_s,
                             :logonCount => group_user[6][:value].to_i,
                             :userPrincipalName => group_user[8][:value].to_s,
                             :whenChanged => group_user[8][:value].to_s,
                             :whenCreated => group_user[8][:value].to_s,
                             :primaryGroupID => group_user[9][:value].to_i,
                             :badPwdCount => group_user[10][:value].to_i
                           }
          run_sqlite_query(db, 'ad_users',sql_param_user)

          # Now associate the user with the group
          sql_param_mapping = { :user_rid => user_rid.to_i, 
                                :group_rid => group_rid.to_i
                              }
          run_sqlite_query(db, 'ad_mapping',sql_param_mapping)

          group_counter += 1
        end
      rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
        print_error("Error(Users): #{e.message.to_s}")
        return
      end
    end

    print_status "Enumerated #{group_counter} group(s)"
    if db and db.close
        f = ::File.size(dbfile.to_s)
        print_status "Database closed: #{dbfile.to_s} at #{f} byte(s)"
    end
  end

 # Run the parameterised SQL query
 def run_sqlite_query(db,table_name,values)
   sql_param_columns = values.keys
   sql_param_bind_params = values.keys.map {|k| ":#{k}"}
   db.execute("replace into #{table_name} (#{sql_param_columns.join(',')}) VALUES (#{sql_param_bind_params.join(',')})", values)
 end

 # Creat the SQLite Database
 def create_sqlite_db
   begin
     filename = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('ad', 5)}.db"
     db = SQLite3::Database.new(filename)
     
     # Create the table for the AD Groups
     db.execute('DROP TABLE IF EXISTS ad_groups')
     sql_table_group = 'CREATE TABLE ad_groups ('\
                          'rid INTEGER PRIMARY KEY NOT NULL,'\
                          'distinguishedName TEXT UNIQUE NOT NULL,'\
                          'sAMAccountName TEXT UNIQUE NOT NULL,'\
                          'description TEXT,'\
                          'whenChanged TEXT,'\
                          'whenCreated TEXT)'
     db.execute(sql_table_group)

     # Create the table for the AD Users
     db.execute('DROP TABLE IF EXISTS ad_users')
     sql_table_users = 'CREATE TABLE ad_users ('\
                          'rid INTEGER PRIMARY KEY NOT NULL,'\
                          'distinguishedName TEXT UNIQUE NOT NULL,'\
                          'description TEXT,'\
                          'displayName TEXT,'\
                          'sAMAccountName TEXT,'\
                          'logonCount INTEGER,'\
                          'primaryGroupID INTEGER,'\
                          'badPwdCount INTEGER,'\
                          'userPrincipalName TEXT UNIQUE,'\
                          'whenCreated TEXT,'\
                          'whenChanged TEXT)'
     db.execute(sql_table_users)

     # Create the table for the mapping between the two (membership)
     db.execute('DROP TABLE IF EXISTS ad_mapping')
     sql_table_mapping = 'CREATE TABLE ad_mapping ('\
                          'user_rid INTEGER NOT NULL,' \
                          'group_rid INTEGER NOT NULL,'\
                          'PRIMARY KEY (user_rid, group_rid),'\
                          'FOREIGN KEY(user_rid) REFERENCES ad_users(rid)'\
                          'FOREIGN KEY(group_rid) REFERENCES ad_groups(rid))'
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
