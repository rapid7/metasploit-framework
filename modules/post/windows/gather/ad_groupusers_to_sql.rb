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
      'Name'         => 'AD Group and User Membership to Offline SQLite Database Recon Module',
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

    register_options([
      OptBool.new('SHOW_USERGROUPS', [true, 'Show the user/group membership in a greppable form.', false]),
      OptBool.new('SHOW_COMPUTERS', [true, 'Show basic computer information in a greppable form.', false]),
      OptInt.new('THREADS', [true, 'Number of threads to spawn to gather membership of each group.', 20])
    ], self.class)
  end

  # Entry point
  def run
    max_search = datastore['MAX_SEARCH']

    db, dbfile = create_sqlite_db
    print_status "Database created: #{dbfile}"

    # Download the list of groups from Active Directory
    vprint_status "Retrieving AD Groups"
    begin
      group_filter = '(objectClass=group)'
      group_fields = ['distinguishedName', 'objectSid', 'samAccountType', 'sAMAccountName', 'whenChanged', 'whenCreated', 'description', 'groupType', 'adminCount']
      groups = query(group_filter, max_search, group_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error("Error(Group): #{e.message}")
      return
    end

    # If no groups were downloaded, there's no point carrying on
    if groups.nil? || groups[:results].empty?
      print_error('No AD groups were discovered')
      return
    end

    # Go through each of the groups and identify the individual users in each group
    vprint_status "Retrieving AD Group Membership"
    users_fields = ['distinguishedName', 'objectSid', 'sAMAccountType', 'sAMAccountName', 'displayName', 'description', 'logonCount', 'userAccountControl', 'userPrincipalName', 'whenChanged', 'whenCreated', 'primaryGroupID', 'badPwdCount','comments', 'title', 'accountExpires', 'adminCount']

    remaining_groups = groups[:results]

    # If the number of threads exceeds the number of groups, reduce them down to the correct number
    threadcount = remaining_groups.count < datastore['THREADS'] ? remaining_groups.count : datastore['THREADS']

    # Loop through each of the groups, creating threads where necessary
    while(not remaining_groups.nil? and not remaining_groups.empty?)
      group_gather = []
      1.upto(threadcount) do
        group_gather << framework.threads.spawn("Module(#{self.refname})", false, remaining_groups.shift) do |individual_group|
	      begin

            next if !individual_group || individual_group.empty? || individual_group.nil?

            # Get the Group RID
	        group_sid, group_rid = sid_hex_to_string(individual_group[1][:value])

	        # Perform the ADSI query to retrieve the effective users in each group (recursion)
	        vprint_status "Retrieving members of #{individual_group[3][:value]}"
	        users_filter = "(&(objectCategory=person)(objectClass=user)(|(memberOf:1.2.840.113556.1.4.1941:=#{individual_group[0][:value]})(primaryGroupID=#{group_rid})))"
	        users_in_group = query(users_filter, max_search, users_fields)
	
	        # Add the group to the database
	        sql_param_group = { rid: group_rid.to_i,
	                            distinguishedName: individual_group[0][:value].to_s,
	                            sAMAccountType: individual_group[2][:value].to_i,
	                            sAMAccountName: individual_group[3][:value].to_s,
	                            whenChanged: individual_group[4][:value].to_s,
	                            whenCreated: individual_group[5][:value].to_s,
	                            description: individual_group[6][:value].to_s,
	                            groupType: individual_group[7][:value].to_i,
	                            adminCount: individual_group[8][:value].to_i,
	                          }
	        run_sqlite_query(db, 'ad_groups', sql_param_group)
	
	        # Go through each group user
            next if users_in_group[:results].empty?
	        users_in_group[:results].each do |group_user|
	          user_sid, user_rid = sid_hex_to_string(group_user[1][:value])
	          print_line "Group [#{individual_group[3][:value]}][#{group_rid}] has member [#{group_user[3][:value]}][#{user_rid}]" if datastore['SHOW_USERGROUPS']
	
	          # Add the group to the database
	          sql_param_user = { rid: user_rid.to_i,
	                             distinguishedName: group_user[0][:value].to_s,
	                             sAMAccountType: group_user[2][:value].to_i,
	                             sAMAccountName: group_user[3][:value].to_s,
	                             displayName: group_user[4][:value].to_s,
	                             description: group_user[5][:value].to_s,
	                             logonCount: group_user[6][:value].to_i,
	                             userAccountControl: group_user[7][:value].to_i,
	                             userPrincipalName: group_user[8][:value].to_s,
	                             whenChanged: group_user[9][:value].to_s,
	                             whenCreated: group_user[10][:value].to_s,
	                             primaryGroupID: group_user[11][:value].to_i,
	                             badPwdCount: group_user[12][:value].to_i,
	                             comments: group_user[13][:value].to_s,
	                             title: group_user[14][:value].to_s,
	                             accountExpires: group_user[15][:value].to_i,
	                             adminCount: group_user[16][:value].to_i
	                           }
	          run_sqlite_query(db, 'ad_users', sql_param_user)
	
	          # Now associate the user with the group
	          sql_param_mapping = { user_rid: user_rid.to_i,
	                                group_rid: group_rid.to_i
	                              }
	          run_sqlite_query(db, 'ad_mapping', sql_param_mapping)
	      end
	
	      rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
	        print_error("Error(Users): #{e.message}")
	        next
	      end
	    end
      end
      group_gather.map { |each_group| each_group.join }
    end

    vprint_status "Retrieving computers"
    begin
      computer_filter = '(objectClass=computer)'
      computer_fields = ['distinguishedName', 'objectSid', 'cn','dNSHostName', 'sAMAccountType', 'sAMAccountName', 'displayName', 'logonCount', 'userAccountControl', 'whenChanged', 'whenCreated', 'primaryGroupID', 'badPwdCount', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion']
      computers = query(computer_filter, max_search, computer_fields)

        computers[:results].each do |comp|
          computer_sid, computer_rid = sid_hex_to_string(comp[1][:value])

          # Add the group to the database
          sql_param_computer = { rid: computer_rid.to_i,
                             distinguishedName: comp[0][:value].to_s,
                             cn: comp[2][:value].to_s,
                             dNSHostName: comp[3][:value].to_s,
                             sAMAccountType: comp[4][:value].to_i,
                             sAMAccountName: comp[5][:value].to_s,
                             displayName: comp[6][:value].to_s,
                             logonCount: comp[7][:value].to_i,
                             userAccountControl: comp[8][:value].to_s,
                             whenChanged: comp[9][:value].to_s,
                             whenCreated: comp[10][:value].to_s,
                             primaryGroupID: comp[11][:value].to_i,
                             badPwdCount: comp[12][:value].to_i,
                             operatingSystem: comp[13][:value].to_s,
                             operatingSystemServicePack: comp[14][:value].to_s,
                             operatingSystemVersion: comp[15][:value].to_s,
                           }
          run_sqlite_query(db, 'ad_computers', sql_param_computer)
          print_line "Computer [#{sql_param_computer[:cn]}][#{sql_param_computer[:dNSHostName]}][#{sql_param_computer[:rid]}]" if datastore['SHOW_USERGROUPS']
        end

    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error("Error(Computers): #{e.message}")
      return
    end

    if db && db.close
      f = ::File.size(dbfile.to_s)
      print_status "Database closed: #{dbfile} at #{f} byte(s)"
    end

  end

  # Run the parameterised SQL query
  def run_sqlite_query(db, table_name, values)
    sql_param_columns = values.keys
    sql_param_bind_params = values.keys.map { |k| ":#{k}" }
    db.execute("replace into #{table_name} (#{sql_param_columns.join(',')}) VALUES (#{sql_param_bind_params.join(',')})", values)
  end

  # Creat the SQLite Database
  def create_sqlite_db
    begin
      obj_temp = ::Dir::Tmpname
      filename = "#{obj_temp.tmpdir}/#{obj_temp.make_tmpname('ad_', 2)}.db"
      db = SQLite3::Database.new(filename)

      # Create the table for the AD Computers
      db.execute('DROP TABLE IF EXISTS ad_computers')
      sql_table_computers = 'CREATE TABLE ad_computers ('\
                           'rid INTEGER PRIMARY KEY NOT NULL,'\
                           'distinguishedName TEXT UNIQUE NOT NULL,'\
                           'cn TEXT,'\
                           'sAMAccountType INTEGER,'\
                           'sAMAccountName TEXT UNIQUE,'\
                           'dNSHostName TEXT,'\
                           'displayName TEXT,'\
                           'logonCount INTEGER,'\
                           'userAccountControl INTEGER,'\
                           'primaryGroupID INTEGER,'\
                           'badPwdCount INTEGER,'\
                           'operatingSystem TEXT,'\
                           'operatingSystemServicePack TEXT,'\
                           'operatingSystemVersion TEXT,'\
                           'whenChanged TEXT,'\
                           'whenCreated TEXT)'
      db.execute(sql_table_computers)

      # Create the table for the AD Groups
      db.execute('DROP TABLE IF EXISTS ad_groups')
      sql_table_group = 'CREATE TABLE ad_groups ('\
                           'rid INTEGER PRIMARY KEY NOT NULL,'\
                           'distinguishedName TEXT UNIQUE NOT NULL,'\
                           'sAMAccountType INTEGER,'\
                           'sAMAccountName TEXT UNIQUE NOT NULL,'\
                           'groupType INTEGER,'\
                           'adminCount INTEGER,'\
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
                           'sAMAccountType INTEGER,'\
                           'sAMAccountName TEXT,'\
                           'logonCount INTEGER,'\
                           'userAccountControl INTEGER,'\
                           'primaryGroupID INTEGER,'\
                           'accountExpires INTEGER,'\
                           'adminCount INTEGER,'\
                           'badPwdCount INTEGER,'\
                           'userPrincipalName TEXT UNIQUE,'\
                           'comments TEXT,'\
                           'title TEXT,'\
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
      print_error("Error(Database): #{e.message}")
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
    [final_sid, sid[-1]]
  end

  def byte2hex(b)
    ret = '%x' % (b.to_i & 0xff)
    ret = '0' + ret if ret.length < 2
    ret
  end
end
