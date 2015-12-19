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
      'Name'         => 'AD Computer, Group and Recursive User Membership to Local SQLite DB',
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
	
            grouptype_int = individual_group[7][:value].to_i # Set this here because it is used a lot below

	        # Add the group to the database
            # groupType parameter interpretation: https://msdn.microsoft.com/en-us/library/windows/desktop/ms675935(v=vs.85).aspx
	        sql_param_group = { rid: group_rid.to_i,
	                            distinguishedName: individual_group[0][:value].to_s,
	                            sAMAccountType: individual_group[2][:value].to_i,
	                            sAMAccountName: individual_group[3][:value].to_s,
	                            whenChanged: individual_group[4][:value].to_s,
	                            whenCreated: individual_group[5][:value].to_s,
	                            description: individual_group[6][:value].to_s,
	                            groupType: individual_group[7][:value].to_i,
	                            adminCount: individual_group[8][:value].to_i,
                                # Specifies a group that is created by the system.
                                GT_GROUP_CREATED_BY_SYSTEM: (grouptype_int & 0x00000001).zero? ? 0 : 1,
                                # Specifies a group with global scope.
                                GT_GROUP_SCOPE_GLOBAL: (grouptype_int & 0x00000002).zero? ? 0 : 1,
                                # Specifies a group with local scope.
                                GT_GROUP_SCOPE_LOCAL: (grouptype_int & 0x00000004).zero? ? 0 : 1,
                                # Specifies a group with universal scope.
                                GT_GROUP_SCOPE_UNIVERSAL: (grouptype_int & 0x00000008).zero? ? 0 : 1,
                                # Specifies an APP_BASIC group for Windows Server Authorization Manager.
                                GT_GROUP_SAM_APP_BASIC: (grouptype_int & 0x00000010).zero? ? 0 : 1,
                                # Specifies an APP_QUERY group for Windows Server Authorization Manager.
                                GT_GROUP_SAM_APP_QUERY: (grouptype_int & 0x00000020).zero? ? 0 : 1,
                                # Specifies a security group. If this flag is not set, then the group is a distribution group.
                                GT_GROUP_SECURITY: (grouptype_int & 0x80000000).zero? ? 0 : 1,
                                # The inverse of the flag above. Technically GT_GROUP_SECURITY=0 makes it a distribution
                                # group so this is arguably redundant, but I have included it for ease. It makes a lot more sense
                                # to set DISTRIBUTION=1 in a query when your mind is on other things to remember that 
                                # DISTRIBUTION is in fact the inverse of SECURITY...:)
                                GT_GROUP_DISTRIBUTION: (grouptype_int & 0x80000000).zero? ? 1 : 0,
	                          }
	        run_sqlite_query(db, 'ad_groups', sql_param_group)
	
	        # Go through each group user
            next if users_in_group[:results].empty?
	        users_in_group[:results].each do |group_user|
	          user_sid, user_rid = sid_hex_to_string(group_user[1][:value])
	          print_line "Group [#{individual_group[3][:value]}][#{group_rid}] has member [#{group_user[3][:value]}][#{user_rid}]" if datastore['SHOW_USERGROUPS']
	
              uac_int = group_user[7][:value].to_i #Set this because it is used so frequently below

	          # Add the group to the database
              # Also parse the ADF_ flags from userAccountControl: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832(v=vs.85).aspx
	          sql_param_user = { rid: user_rid.to_i,
	                             distinguishedName: group_user[0][:value].to_s,
	                             sAMAccountType: group_user[2][:value].to_i,
	                             sAMAccountName: group_user[3][:value].to_s,
	                             displayName: group_user[4][:value].to_s,
	                             description: group_user[5][:value].to_s,
	                             logonCount: group_user[6][:value].to_i,
	                             userAccountControl: uac_int,
	                             userPrincipalName: group_user[8][:value].to_s,
	                             whenChanged: group_user[9][:value].to_s,
	                             whenCreated: group_user[10][:value].to_s,
	                             primaryGroupID: group_user[11][:value].to_i,
	                             badPwdCount: group_user[12][:value].to_i,
	                             comments: group_user[13][:value].to_s,
	                             title: group_user[14][:value].to_s,
	                             accountExpires: group_user[15][:value].to_i,
                                 #Indicates that a given object has had its ACLs changed to a more secure value by the 
                                 #system because it was a member of one of the administrative groups (directly or transitively).
	                             adminCount: group_user[16][:value].to_i,
                                 #The login script is executed
                                 ADS_UF_SCRIPT: (uac_int & 0x00000001).zero? ? 0 : 1, 
                                 #The user account is disabled.
                                 ADS_UF_ACCOUNTDISABLE: (uac_int & 0x00000002).zero? ? 0 : 1, 
                                 #The home directory is required.
                                 ADS_UF_HOMEDIR_REQUIRED: (uac_int & 0x00000008).zero? ? 0 : 1, 
                                 #The account is currently locked out.
                                 ADS_UF_LOCKOUT: (uac_int & 0x00000010).zero? ? 0 : 1, 
                                 #No password is required.
                                 ADS_UF_PASSWD_NOTREQD: (uac_int & 0x00000020).zero? ? 0 : 1,
                                 #The user cannot change the password.
                                 ADS_UF_PASSWD_CANT_CHANGE: (uac_int & 0x00000040).zero? ? 0 : 1, 
                                 #The user can send an encrypted password.
                                 ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: (uac_int & 0x00000080).zero? ? 0 : 1, 
                                 #This is an account for users whose primary account is in another domain. This account
                                 #provides user access to this domain, but not to any domain that trusts this domain.
                                 #Also known as a local user account.
                                 ADS_UF_TEMP_DUPLICATE_ACCOUNT: (uac_int & 0x00000100).zero? ? 0 : 1, 
                                 #This is a default account type that represents a typical user.
                                 ADS_UF_NORMAL_ACCOUNT: (uac_int & 0x00000200).zero? ? 0 : 1, 
                                 #This is a permit to trust account for a system domain that trusts other domains.
                                 ADS_UF_INTERDOMAIN_TRUST_ACCOUNT: (uac_int & 0x00000800).zero? ? 0 : 1, 
                                 #This is a computer account for a computer that is a member of this domain.
                                 ADS_UF_WORKSTATION_TRUST_ACCOUNT: (uac_int & 0x00001000).zero? ? 0 : 1, 
                                 #This is a computer account for a system backup domain controller that is a member of this domain.
                                 ADS_UF_SERVER_TRUST_ACCOUNT: (uac_int & 0x00002000).zero? ? 0 : 1, 
                                 #The password for this account will never expire.
                                 ADS_UF_DONT_EXPIRE_PASSWD: (uac_int & 0x00010000).zero? ? 0 : 1, 
                                 #This is an MNS logon account.
                                 ADS_UF_MNS_LOGON_ACCOUNT: (uac_int & 0x00020000).zero? ? 0 : 1, 
                                 #The user must log on using a smart card.
                                 ADS_UF_SMARTCARD_REQUIRED: (uac_int & 0x00040000).zero? ? 0 : 1, 
                                 #The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
                                 #Any such service can impersonate a client requesting the service.
                                 ADS_UF_TRUSTED_FOR_DELEGATION: (uac_int & 0x00080000).zero? ? 0 : 1, 
                                 #The security context of the user will not be delegated to a service even if the service 
                                 #account is set as trusted for Kerberos delegation.
                                 ADS_UF_NOT_DELEGATED: (uac_int & 0x00100000).zero? ? 0 : 1, 
                                 #Restrict this principal to use only Data #Encryption Standard (DES) encryption types for keys.
                                 ADS_UF_USE_DES_KEY_ONLY: (uac_int & 0x00200000).zero? ? 0 : 1, 
                                 #This account does not require Kerberos pre-authentication for logon.
                                 ADS_UF_DONT_REQUIRE_PREAUTH: (uac_int & 0x00400000).zero? ? 0 : 1, 
                                 #The password has expired
                                 ADS_UF_PASSWORD_EXPIRED: (uac_int & 0x00800000).zero? ? 0 : 1, 
                                 #The account is enabled for delegation. This is a security-sensitive setting; accounts with
                                 #this option enabled should be strictly controlled. This setting enables a service running 
                                 #under the account to assume a client identity and authenticate as that user to other remote 
                                 #servers on the network.
                                 ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: (uac_int & 0x01000000).zero? ? 0 : 1 
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

          uac_int = comp[8][:value].to_i #Set this because it is used so frequently below

          # Add the group to the database
          # Also parse the ADF_ flags from userAccountControl: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832(v=vs.85).aspx
          # Note that userAccountControl is basically the same for a computer as a user; this is because a computer account is derived from a user account
          # (if you look at the objectClass for a computer account, it includes 'user') and, for efficiency, we should really store it all in one
          # table. However, the reality is that it will get annoying for users to have to remember to use the userAccountControl flags to work out whether
          # its a user or a computer and so, for convenience and ease of use, I have put them in completely separate tables.
          sql_param_computer = { rid: computer_rid.to_i,
                             distinguishedName: comp[0][:value].to_s,
                             cn: comp[2][:value].to_s,
                             dNSHostName: comp[3][:value].to_s,
                             sAMAccountType: comp[4][:value].to_i,
                             sAMAccountName: comp[5][:value].to_s,
                             displayName: comp[6][:value].to_s,
                             logonCount: comp[7][:value].to_i,
                             userAccountControl: uac_int,
                             whenChanged: comp[9][:value].to_s,
                             whenCreated: comp[10][:value].to_s,
                             primaryGroupID: comp[11][:value].to_i,
                             badPwdCount: comp[12][:value].to_i,
                             operatingSystem: comp[13][:value].to_s,
                             operatingSystemServicePack: comp[14][:value].to_s,
                             operatingSystemVersion: comp[15][:value].to_s,
                             #The login script is executed
                             ADS_UF_SCRIPT: (uac_int & 0x00000001).zero? ? 0 : 1, 
                             #The user account is disabled.
                             ADS_UF_ACCOUNTDISABLE: (uac_int & 0x00000002).zero? ? 0 : 1, 
                             #The home directory is required.
                             ADS_UF_HOMEDIR_REQUIRED: (uac_int & 0x00000008).zero? ? 0 : 1, 
                             #The account is currently locked out.
                             ADS_UF_LOCKOUT: (uac_int & 0x00000010).zero? ? 0 : 1, 
                             #No password is required.
                             ADS_UF_PASSWD_NOTREQD: (uac_int & 0x00000020).zero? ? 0 : 1,
                             #The user cannot change the password.
                             ADS_UF_PASSWD_CANT_CHANGE: (uac_int & 0x00000040).zero? ? 0 : 1, 
                             #The user can send an encrypted password.
                             ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: (uac_int & 0x00000080).zero? ? 0 : 1, 
                             #This is an account for users whose primary account is in another domain. This account
                             #provides user access to this domain, but not to any domain that trusts this domain.
                             #Also known as a local user account.
                             ADS_UF_TEMP_DUPLICATE_ACCOUNT: (uac_int & 0x00000100).zero? ? 0 : 1, 
                             #This is a default account type that represents a typical user.
                             ADS_UF_NORMAL_ACCOUNT: (uac_int & 0x00000200).zero? ? 0 : 1, 
                             #This is a permit to trust account for a system domain that trusts other domains.
                             ADS_UF_INTERDOMAIN_TRUST_ACCOUNT: (uac_int & 0x00000800).zero? ? 0 : 1, 
                             #This is a computer account for a computer that is a member of this domain.
                             ADS_UF_WORKSTATION_TRUST_ACCOUNT: (uac_int & 0x00001000).zero? ? 0 : 1, 
                             #This is a computer account for a system backup domain controller that is a member of this domain.
                             ADS_UF_SERVER_TRUST_ACCOUNT: (uac_int & 0x00002000).zero? ? 0 : 1, 
                             #The password for this account will never expire.
                             ADS_UF_DONT_EXPIRE_PASSWD: (uac_int & 0x00010000).zero? ? 0 : 1, 
                             #This is an MNS logon account.
                             ADS_UF_MNS_LOGON_ACCOUNT: (uac_int & 0x00020000).zero? ? 0 : 1, 
                             #The user must log on using a smart card.
                             ADS_UF_SMARTCARD_REQUIRED: (uac_int & 0x00040000).zero? ? 0 : 1, 
                             #The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
                             #Any such service can impersonate a client requesting the service.
                             ADS_UF_TRUSTED_FOR_DELEGATION: (uac_int & 0x00080000).zero? ? 0 : 1, 
                             #The security context of the user will not be delegated to a service even if the service 
                             #account is set as trusted for Kerberos delegation.
                             ADS_UF_NOT_DELEGATED: (uac_int & 0x00100000).zero? ? 0 : 1, 
                             #Restrict this principal to use only Data #Encryption Standard (DES) encryption types for keys.
                             ADS_UF_USE_DES_KEY_ONLY: (uac_int & 0x00200000).zero? ? 0 : 1, 
                             #This account does not require Kerberos pre-authentication for logon.
                             ADS_UF_DONT_REQUIRE_PREAUTH: (uac_int & 0x00400000).zero? ? 0 : 1, 
                             #The password has expired
                             ADS_UF_PASSWORD_EXPIRED: (uac_int & 0x00800000).zero? ? 0 : 1, 
                             #The account is enabled for delegation. This is a security-sensitive setting; accounts with
                             #this option enabled should be strictly controlled. This setting enables a service running 
                             #under the account to assume a client identity and authenticate as that user to other remote 
                             #servers on the network.
                             ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: (uac_int & 0x01000000).zero? ? 0 : 1 
                           }
          run_sqlite_query(db, 'ad_computers', sql_param_computer)
          print_line "Computer [#{sql_param_computer[:cn]}][#{sql_param_computer[:dNSHostName]}][#{sql_param_computer[:rid]}]" if datastore['SHOW_USERGROUPS']
        end

    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error("Error(Computers): #{e.message}")
      return
    end

    # Finished enumeration, now safely close the database
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
                           'sAMAccountName TEXT UNIQUE NOT NULL,'\
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
                           'whenCreated TEXT,'\
						   'ADS_UF_SCRIPT INTEGER,'\
						   'ADS_UF_ACCOUNTDISABLE INTEGER,'\
						   'ADS_UF_HOMEDIR_REQUIRED INTEGER,'\
						   'ADS_UF_LOCKOUT INTEGER,'\
						   'ADS_UF_PASSWD_NOTREQD INTEGER,'\
						   'ADS_UF_PASSWD_CANT_CHANGE INTEGER,'\
						   'ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED INTEGER,'\
						   'ADS_UF_TEMP_DUPLICATE_ACCOUNT INTEGER,'\
						   'ADS_UF_NORMAL_ACCOUNT INTEGER,'\
						   'ADS_UF_INTERDOMAIN_TRUST_ACCOUNT INTEGER,'\
						   'ADS_UF_WORKSTATION_TRUST_ACCOUNT INTEGER,'\
						   'ADS_UF_SERVER_TRUST_ACCOUNT INTEGER,'\
						   'ADS_UF_DONT_EXPIRE_PASSWD INTEGER,'\
						   'ADS_UF_MNS_LOGON_ACCOUNT INTEGER,'\
						   'ADS_UF_SMARTCARD_REQUIRED INTEGER,'\
						   'ADS_UF_TRUSTED_FOR_DELEGATION INTEGER,'\
						   'ADS_UF_NOT_DELEGATED INTEGER,'\
						   'ADS_UF_USE_DES_KEY_ONLY INTEGER,'\
						   'ADS_UF_DONT_REQUIRE_PREAUTH INTEGER,'\
						   'ADS_UF_PASSWORD_EXPIRED INTEGER,'\
						   'ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION INTEGER)'
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
                           'whenCreated TEXT,'\
                           'GT_GROUP_CREATED_BY_SYSTEM INTEGER,'\
                           'GT_GROUP_SCOPE_GLOBAL INTEGER,'\
                           'GT_GROUP_SCOPE_LOCAL INTEGER,'\
                           'GT_GROUP_SCOPE_UNIVERSAL INTEGER,'\
                           'GT_GROUP_SAM_APP_BASIC INTEGER,'\
                           'GT_GROUP_SAM_APP_QUERY INTEGER,'\
                           'GT_GROUP_SECURITY INTEGER,'\
                           'GT_GROUP_DISTRIBUTION INTEGER)'
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
                           'whenChanged TEXT,'\
						   'ADS_UF_SCRIPT INTEGER,'\
						   'ADS_UF_ACCOUNTDISABLE INTEGER,'\
						   'ADS_UF_HOMEDIR_REQUIRED INTEGER,'\
						   'ADS_UF_LOCKOUT INTEGER,'\
						   'ADS_UF_PASSWD_NOTREQD INTEGER,'\
						   'ADS_UF_PASSWD_CANT_CHANGE INTEGER,'\
						   'ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED INTEGER,'\
						   'ADS_UF_TEMP_DUPLICATE_ACCOUNT INTEGER,'\
						   'ADS_UF_NORMAL_ACCOUNT INTEGER,'\
						   'ADS_UF_INTERDOMAIN_TRUST_ACCOUNT INTEGER,'\
						   'ADS_UF_WORKSTATION_TRUST_ACCOUNT INTEGER,'\
						   'ADS_UF_SERVER_TRUST_ACCOUNT INTEGER,'\
						   'ADS_UF_DONT_EXPIRE_PASSWD INTEGER,'\
						   'ADS_UF_MNS_LOGON_ACCOUNT INTEGER,'\
						   'ADS_UF_SMARTCARD_REQUIRED INTEGER,'\
						   'ADS_UF_TRUSTED_FOR_DELEGATION INTEGER,'\
						   'ADS_UF_NOT_DELEGATED INTEGER,'\
						   'ADS_UF_USE_DES_KEY_ONLY INTEGER,'\
						   'ADS_UF_DONT_REQUIRE_PREAUTH INTEGER,'\
						   'ADS_UF_PASSWORD_EXPIRED INTEGER,'\
						   'ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION INTEGER)'
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

      # Now create the computer query view (which joins lookup tables and prefixes everything with c_)
      # This is essentially to maintain namespace (less of an issue for computers but
      # I have done it for this table too in order to maintain consistency)
      db.execute('DROP VIEW IF EXISTS view_ad_computers')
      sql_view_computers = 'CREATE VIEW view_ad_computers AS SELECT '\
                               'rid AS c_rid,'\
                               'distinguishedName AS c_distinguishedName,'\
                               'cn AS c_cn,'\
                               'sAMAccountType AS c_sAMAccountType,'\
                               'ref_sAMAccountType.name AS c_sAMAccountType_Name,'\
                               'sAMAccountName AS c_sAMAccountName,'\
                               'dNSHostName AS c_dNSHostName,'\
                               'displayName AS c_displayName,'\
                               'logonCount AS c_logonCount,'\
                               'userAccountControl AS c_userAccountControl,'\
                               'primaryGroupID AS c_primaryGroupID,'\
                               'badPwdCount AS c_badPwdCount,'\
                               'operatingSystem AS c_operatingSystem,'\
                               'operatingSystemServicePack AS c_operatingSystemServicePack,'\
                               'operatingSystemVersion AS c_operatingSystemVersion,'\
                               'whenCreated AS c_whenCreated,'\
                               'whenChanged AS c_whenChanged,'\
       						   'ADS_UF_SCRIPT AS c_ADS_UF_SCRIPT,'\
       						   'ADS_UF_ACCOUNTDISABLE AS c_ADS_UF_ACCOUNTDISABLE,'\
       						   'ADS_UF_HOMEDIR_REQUIRED AS c_ADS_UF_HOMEDIR_REQUIRED,'\
       						   'ADS_UF_LOCKOUT AS c_ADS_UF_LOCKOUT,'\
       						   'ADS_UF_PASSWD_NOTREQD AS c_ADS_UF_PASSWD_NOTREQD,'\
       						   'ADS_UF_PASSWD_CANT_CHANGE AS c_ADS_UF_PASSWD_CANT_CHANGE,'\
       						   'ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED AS c_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,'\
       						   'ADS_UF_TEMP_DUPLICATE_ACCOUNT AS c_ADS_UF_TEMP_DUPLICATE_ACCOUNT,'\
       						   'ADS_UF_NORMAL_ACCOUNT AS c_ADS_UF_NORMAL_ACCOUNT,'\
       						   'ADS_UF_INTERDOMAIN_TRUST_ACCOUNT AS c_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT,'\
       						   'ADS_UF_WORKSTATION_TRUST_ACCOUNT AS c_ADS_UF_WORKSTATION_TRUST_ACCOUNT,'\
       						   'ADS_UF_SERVER_TRUST_ACCOUNT AS c_ADS_UF_SERVER_TRUST_ACCOUNT,'\
       						   'ADS_UF_DONT_EXPIRE_PASSWD AS c_ADS_UF_DONT_EXPIRE_PASSWD,'\
       						   'ADS_UF_MNS_LOGON_ACCOUNT AS c_ADS_UF_MNS_LOGON_ACCOUNT,'\
       						   'ADS_UF_SMARTCARD_REQUIRED AS c_ADS_UF_SMARTCARD_REQUIRED,'\
       						   'ADS_UF_TRUSTED_FOR_DELEGATION AS c_ADS_UF_TRUSTED_FOR_DELEGATION,'\
       						   'ADS_UF_NOT_DELEGATED AS c_ADS_UF_NOT_DELEGATED,'\
       						   'ADS_UF_USE_DES_KEY_ONLY AS c_ADS_UF_USE_DES_KEY_ONLY,'\
       						   'ADS_UF_DONT_REQUIRE_PREAUTH AS c_ADS_UF_DONT_REQUIRE_PREAUTH,'\
       						   'ADS_UF_PASSWORD_EXPIRED AS c_ADS_UF_PASSWORD_EXPIRED,'\
       						   'ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION AS c_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION '\
       						   'FROM ad_computers LEFT JOIN ref_sAMAccountType ON ref_sAMAccountType.id = ad_computers.sAMAccountType'
      db.execute(sql_view_computers)

      # Create the view for the AD Groups
      db.execute('DROP VIEW IF EXISTS view_ad_groups')
      sql_view_group = 'CREATE VIEW view_ad_groups AS SELECT '\
                           'rid AS u_rid,'\
                           'distinguishedName AS u_distinguishedName,'\
                           'sAMAccountType AS u_sAMAccountType,'\
                           'sAMAccountName AS u_sAMAccountName,'\
                           'groupType AS u_groupType,'\
                           'adminCount AS u_adminCount,'\
                           'description AS u_description,'\
                           'whenChanged AS u_whenChanged,'\
                           'whenCreated AS u_whenCreated,'\
                           'GT_GROUP_CREATED_BY_SYSTEM AS u_GT_GROUP_CREATED_BY_SYSTEM,'\
                           'GT_GROUP_SCOPE_GLOBAL AS u_GT_GROUP_SCOPE_GLOBAL,'\
                           'GT_GROUP_SCOPE_LOCAL AS u_GT_GROUP_SCOPE_LOCAL,'\
                           'GT_GROUP_SCOPE_UNIVERSAL AS u_GT_GROUP_SCOPE_UNIVERSAL,'\
                           'GT_GROUP_SAM_APP_BASIC AS u_GT_GROUP_SAM_APP_BASIC,'\
                           'GT_GROUP_SAM_APP_QUERY AS u_GT_GROUP_SAM_APP_QUERY,'\
                           'GT_GROUP_SECURITY AS u_GT_GROUP_SECURITY,'\
                           'GT_GROUP_DISTRIBUTION as U_GT_GROUP_DISTRIBUTION'
      db.execute(sql_view_group)

      # Create the view for the AD Users
      db.execute('DROP VIEW IF EXISTS view_ad_users')
      sql_view_users = 'CREATE VIEW view_ad_users AS SELECT '\
                           'rid AS g_rid,'\
                           'distinguishedName AS g_distinguishedName,'\
                           'description AS g_description,'\
                           'displayName AS g_displayName,'\
                           'sAMAccountType AS g_sAMAccountType,'\
                           'sAMAccountName AS g_sAMAccountName,'\
                           'logonCount AS g_logonCount,'\
                           'userAccountControl AS g_userAccountControl,'\
                           'primaryGroupID AS g_primaryGroupID,'\
                           'accountExpires AS g_accountExpires,'\
                           'adminCount AS g_adminCount,'\
                           'badPwdCount AS g_badPwdCount,'\
                           'userPrincipalName AS g_userPrincipalName,'\
                           'comments AS g_comments,'\
                           'title AS g_title,'\
                           'whenCreated AS g_whenCreated,'\
                           'whenChanged AS g_whenChanged,'\
						   'ADS_UF_SCRIPT AS g_ADS_UF_SCRIPT,'\
						   'ADS_UF_ACCOUNTDISABLE AS g_ADS_UF_ACCOUNTDISABLE,'\
						   'ADS_UF_HOMEDIR_REQUIRED AS g_ADS_UF_HOMEDIR_REQUIRED,'\
						   'ADS_UF_LOCKOUT AS g_ADS_UF_LOCKOUT,'\
						   'ADS_UF_PASSWD_NOTREQD AS g_ADS_UF_PASSWD_NOTREQD,'\
						   'ADS_UF_PASSWD_CANT_CHANGE AS g_ADS_UF_PASSWD_CANT_CHANGE,'\
						   'ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED AS g_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,'\
						   'ADS_UF_TEMP_DUPLICATE_ACCOUNT AS g_ADS_UF_TEMP_DUPLICATE_ACCOUNT,'\
						   'ADS_UF_NORMAL_ACCOUNT AS g_ADS_UF_NORMAL_ACCOUNT,'\
						   'ADS_UF_INTERDOMAIN_TRUST_ACCOUNT AS g_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT,'\
						   'ADS_UF_WORKSTATION_TRUST_ACCOUNT AS g_ADS_UF_WORKSTATION_TRUST_ACCOUNT,'\
						   'ADS_UF_SERVER_TRUST_ACCOUNT AS g_ADS_UF_SERVER_TRUST_ACCOUNT,'\
						   'ADS_UF_DONT_EXPIRE_PASSWD AS g_ADS_UF_DONT_EXPIRE_PASSWD,'\
						   'ADS_UF_MNS_LOGON_ACCOUNT AS g_ADS_UF_MNS_LOGON_ACCOUNT,'\
						   'ADS_UF_SMARTCARD_REQUIRED AS g_ADS_UF_SMARTCARD_REQUIRED,'\
						   'ADS_UF_TRUSTED_FOR_DELEGATION AS g_ADS_UF_TRUSTED_FOR_DELEGATION,'\
						   'ADS_UF_NOT_DELEGATED AS g_ADS_UF_NOT_DELEGATED,'\
						   'ADS_UF_USE_DES_KEY_ONLY AS g_ADS_UF_USE_DES_KEY_ONLY,'\
						   'ADS_UF_DONT_REQUIRE_PREAUTH AS g_ADS_UF_DONT_REQUIRE_PREAUTH,'\
						   'ADS_UF_PASSWORD_EXPIRED AS g_ADS_UF_PASSWORD_EXPIRED,'\
						   'ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION as g_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION'
      db.execute(sql_view_users)
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
