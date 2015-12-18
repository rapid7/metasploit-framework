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
      OptString.new('GROUP_FILTER', [true, 'Filter to identify groups', '(objectClass=group)']),
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
      group_fields = ['distinguishedName', 'objectSid', 'samAccountType', 'sAMAccountName', 'whenChanged', 'whenCreated', 'description', 'groupType', 'adminCount']
      groups = query(datastore['GROUP_FILTER'], max_search, group_fields)
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
              # Also parse the ADF_ flags from userAccountControl: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832(v=vs.85).aspx
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
	                             adminCount: group_user[16][:value].to_i,
                              # The login script is executed
                              ADS_UF_SCRIPT: (group_user[7][:value].to_i & 0x00000001) ? 1 : 0, 
                              #The user account is disabled.
                              ADS_UF_ACCOUNTDISABLE: (group_user[7][:value].to_i & 0x00000002) ? 1 : 0, 
                              #The home directory is required.
                              ADS_UF_HOMEDIR_REQUIRED: (group_user[7][:value].to_i & 0x00000008) ? 1 : 0, 
                              #The account is currently locked out.
                              ADS_UF_LOCKOUT: (group_user[7][:value].to_i & 0x00000010) ? 1 : 0, 
                              #No password is required.
                              ADS_UF_PASSWD_NOTREQD: (group_user[7][:value].to_i & 0x00000020) ? 1 : 0,
                              #The user cannot change the password.
                              ADS_UF_PASSWD_CANT_CHANGE: (group_user[7][:value].to_i & 0x00000040) ? 1 : 0, 
                              #The user can send an encrypted password.
                              ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: (group_user[7][:value].to_i & 0x00000080) ? 1 : 0, 
                              #This is an account for users whose primary account is in another domain. This account
                              #provides user access to this domain, but not to any domain that trusts this domain.
                              #Also known as a local user account.
                              ADS_UF_TEMP_DUPLICATE_ACCOUNT: (group_user[7][:value].to_i & 0x00000100) ? 1 : 0, 
                              #This is a default account type that represents a typical user.
                              ADS_UF_NORMAL_ACCOUNT: (group_user[7][:value].to_i & 0x00000200) ? 1 : 0, 
                              #This is a permit to trust account for a system domain that trusts other domains.
                              ADS_UF_INTERDOMAIN_TRUST_ACCOUNT: (group_user[7][:value].to_i & 0x00000800) ? 1 : 0, 
                              #This is a computer account for a computer that is a member of this domain.
                              ADS_UF_WORKSTATION_TRUST_ACCOUNT: (group_user[7][:value].to_i & 0x00001000) ? 1 : 0, 
                              #This is a computer account for a system backup domain controller that is a member of this domain.
                              ADS_UF_SERVER_TRUST_ACCOUNT: (group_user[7][:value].to_i & 0x00002000) ? 1 : 0, 
                              #The password for this account will never expire.
                              ADS_UF_DONT_EXPIRE_PASSWD: (group_user[7][:value].to_i & 0x00010000) ? 1 : 0, 
                              #This is an MNS logon account.
                              ADS_UF_MNS_LOGON_ACCOUNT: (group_user[7][:value].to_i & 0x00020000) ? 1 : 0, 
                              #The user must log on using a smart card.
                              ADS_UF_SMARTCARD_REQUIRED: (group_user[7][:value].to_i & 0x00040000) ? 1 : 0, 
                              #The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
                              #Any such service can impersonate a client requesting the service.
                              ADS_UF_TRUSTED_FOR_DELEGATION: (group_user[7][:value].to_i & 0x00080000) ? 1 : 0, 
                              #The security context of the user will not be delegated to a service even if the service 
                              #account is set as trusted for Kerberos delegation.
                              ADS_UF_NOT_DELEGATED: (group_user[7][:value].to_i & 0x00100000) ? 1 : 0, 
                              #Restrict this principal to use only Data #Encryption Standard (DES) encryption types for keys.
                              ADS_UF_USE_DES_KEY_ONLY: (group_user[7][:value].to_i & 0x00200000) ? 1 : 0, 
                              #This account does not require Kerberos pre-authentication for logon.
                              ADS_UF_DONT_REQUIRE_PREAUTH: (group_user[7][:value].to_i & 0x00400000) ? 1 : 0, 
                              #The password has expired
                              ADS_UF_PASSWORD_EXPIRED: (group_user[7][:value].to_i & 0x00800000) ? 1 : 0, 
                              #The account is enabled for delegation. This is a security-sensitive setting; accounts with
                              #this option enabled should be strictly controlled. This setting enables a service running 
                              #under the account to assume a client identity and authenticate as that user to other remote 
                              #servers on the network.
                              ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: (group_user[7][:value].to_i & 0x01000000) ? 1 : 0 
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

      # Create the reference table for sAMAccountType
      # https://msdn.microsoft.com/en-us/library/windows/desktop/ms679637(v=vs.85).aspx
      db.execute('DROP TABLE IF EXISTS ref_sAMAccountType')
      sql_table_ref_sac = 'CREATE TABLE ref_sAMAccountType ('\
                           'id INTEGER PRIMARY KEY NOT NULL,'\
                           'name TEXT UNIQUE NOT NULL)'
      db.execute(sql_table_ref_sac)

      # Now insert the data into the sAMAccoutType reference table
      # SQLite v3.7+ supports a rather convoluted UNION SELECT way of adding multiple rows
      # in one query but for the sake of simplicity and readability, I have just left these as
      # separate insert statements. Its hardly an efficiency problem given the rest of the module!
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_DOMAIN_OBJECT',0)")
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_GROUP_OBJECT',0x10000000)") 
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_NON_SECURITY_GROUP_OBJECT',0x10000001)") 
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_ALIAS_OBJECT',0x20000000)") 
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_NON_SECURITY_ALIAS_OBJECT',0x20000001)") 
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_NORMAL_USER_ACCOUNT',0x30000000)")
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_MACHINE_ACCOUNT',0x30000001)")
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_TRUST_ACCOUNT',0x30000002)")
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_APP_BASIC_GROUP',0x40000000)")
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_APP_QUERY_GROUP',0x40000001)")
  	  db.execute("insert into ref_sAMAccountType (name,id) VALUES ('SAM_ACCOUNT_TYPE_MAX',0x7fffffff)")

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
