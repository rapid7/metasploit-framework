##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sqlite3'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::LDAP

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
      OptString.new('GROUP_FILTER', [false, 'Additional LDAP filters to use when searching for initial groups', '']),
      OptBool.new('SHOW_USERGROUPS', [true, 'Show the user/group membership in a greppable form to the console.', false]),
      OptBool.new('SHOW_COMPUTERS', [true, 'Show basic computer information in a greppable form to the console.', false]),
      OptInt.new('THREADS', [true, 'Number of threads to spawn to gather membership of each group.', 20])
    ])
  end

  # Entry point
  def run
    max_search = datastore['MAX_SEARCH']

    db, dbfile = create_sqlite_db
    print_status "Database created: #{dbfile}"

    # Download the list of groups from Active Directory
    vprint_status "Retrieving AD Groups"
    begin
      group_fields = ['distinguishedName', 'objectSid', 'samAccountType', 'sAMAccountName', 'whenChanged', 'whenCreated', 'description', 'groupType', 'adminCount', 'comment', 'managedBy', 'cn']
      if datastore['GROUP_FILTER'].nil? || datastore['GROUP_FILTER'].empty?
        group_query = "(objectClass=group)"
      else
        group_query = "(&(objectClass=group)(#{datastore['GROUP_FILTER']}))"
      end
      groups = query(group_query, max_search, group_fields)
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
    vprint_status "Groups retrieval completed: #{groups[:results].size} group(s)"
    vprint_status "Retrieving AD Group Membership"
    users_fields = ['distinguishedName', 'objectSid', 'sAMAccountType', 'sAMAccountName', 'displayName', 'description', 'logonCount', 'userAccountControl', 'userPrincipalName', 'whenChanged', 'whenCreated', 'primaryGroupID', 'badPwdCount', 'comment', 'title', 'cn', 'adminCount', 'manager']

    remaining_groups = groups[:results]

    # If the number of threads exceeds the number of groups, reduce them down to the correct number
    threadcount = remaining_groups.count < datastore['THREADS'] ? remaining_groups.count : datastore['THREADS']

    # Loop through each of the groups, creating threads where necessary
    while !remaining_groups.nil? && !remaining_groups.empty?
      group_gather = []
      1.upto(threadcount) do
        group_gather << framework.threads.spawn("Module(#{refname})", false, remaining_groups.shift) do |individual_group|
          begin

            next if !individual_group || individual_group.empty? || individual_group.nil?

            # Get the Group RID
            group_rid = get_rid(individual_group[1][:value]).to_i

            # Perform the ADSI query to retrieve the effective users in each group (recursion)
            vprint_status "Retrieving members of #{individual_group[3][:value]}"
            users_filter = "(&(objectCategory=person)(objectClass=user)(|(memberOf:1.2.840.113556.1.4.1941:=#{individual_group[0][:value]})(primaryGroupID=#{group_rid})))"
            users_in_group = query(users_filter, max_search, users_fields)

            grouptype_int = individual_group[7][:value].to_i # Set this here because it is used a lot below
            sat_int = individual_group[2][:value].to_i

            # Add the group to the database
            # groupType parameter interpretation: https://msdn.microsoft.com/en-us/library/windows/desktop/ms675935(v=vs.85).aspx
            # Note that the conversions to UTF-8 are necessary because of the way SQLite detects column type affinity
            # Turns out that the 'fix' is documented in https://github.com/rails/rails/issues/1965
            sql_param_group = { g_rid: group_rid,
                                g_distinguishedName: individual_group[0][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                g_sAMAccountType: sat_int,
                                g_sAMAccountName: individual_group[3][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                g_whenChanged: individual_group[4][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                g_whenCreated: individual_group[5][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                g_description: individual_group[6][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                g_groupType: grouptype_int,
                                g_adminCount: individual_group[8][:value].to_i,
                                g_comment: individual_group[9][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                g_managedBy: individual_group[10][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                g_cn: individual_group[11][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                # Specifies a group that is created by the system.
                                g_GT_GROUP_CREATED_BY_SYSTEM: (grouptype_int & 0x00000001).zero? ? 0 : 1,
                                # Specifies a group with global scope.
                                g_GT_GROUP_SCOPE_GLOBAL: (grouptype_int & 0x00000002).zero? ? 0 : 1,
                                # Specifies a group with local scope.
                                g_GT_GROUP_SCOPE_LOCAL: (grouptype_int & 0x00000004).zero? ? 0 : 1,
                                # Specifies a group with universal scope.
                                g_GT_GROUP_SCOPE_UNIVERSAL: (grouptype_int & 0x00000008).zero? ? 0 : 1,
                                # Specifies an APP_BASIC group for Windows Server Authorization Manager.
                                g_GT_GROUP_SAM_APP_BASIC: (grouptype_int & 0x00000010).zero? ? 0 : 1,
                                # Specifies an APP_QUERY group for Windows Server Authorization Manager.
                                g_GT_GROUP_SAM_APP_QUERY: (grouptype_int & 0x00000020).zero? ? 0 : 1,
                                # Specifies a security group. If this flag is not set, then the group is a distribution group.
                                g_GT_GROUP_SECURITY: (grouptype_int & 0x80000000).zero? ? 0 : 1,
                                # The inverse of the flag above. Technically GT_GROUP_SECURITY=0 makes it a distribution
                                # group so this is arguably redundant, but I have included it for ease. It makes a lot more sense
                                # to set DISTRIBUTION=1 in a query when your mind is on other things to remember that
                                # DISTRIBUTION is in fact the inverse of SECURITY...:)
                                g_GT_GROUP_DISTRIBUTION: (grouptype_int & 0x80000000).zero? ? 1 : 0,
                                # Now add sAMAccountType constants
                                g_SAM_DOMAIN_OBJECT: (sat_int == 0) ? 1 : 0,
                                g_SAM_GROUP_OBJECT: (sat_int == 0x10000000) ? 1 : 0,
                                g_SAM_NON_SECURITY_GROUP_OBJECT: (sat_int == 0x10000001) ? 1 : 0,
                                g_SAM_ALIAS_OBJECT: (sat_int == 0x20000000) ? 1 : 0,
                                g_SAM_NON_SECURITY_ALIAS_OBJECT: (sat_int == 0x20000001) ? 1 : 0,
                                g_SAM_NORMAL_USER_ACCOUNT: (sat_int == 0x30000000) ? 1 : 0,
                                g_SAM_MACHINE_ACCOUNT: (sat_int == 0x30000001) ? 1 : 0,
                                g_SAM_TRUST_ACCOUNT: (sat_int == 0x30000002) ? 1 : 0,
                                g_SAM_APP_BASIC_GROUP: (sat_int == 0x40000000) ? 1 : 0,
                                g_SAM_APP_QUERY_GROUP: (sat_int == 0x40000001) ? 1 : 0,
                                g_SAM_ACCOUNT_TYPE_MAX: (sat_int == 0x7fffffff) ? 1 : 0
                              }
            run_sqlite_query(db, 'ad_groups', sql_param_group)

            # Go through each group user
            next if users_in_group[:results].empty?
            users_in_group[:results].each do |group_user|
              user_rid = get_rid(group_user[1][:value]).to_i
              print_line "Group [#{individual_group[3][:value]}][#{group_rid}] has member [#{group_user[3][:value]}][#{user_rid}]" if datastore['SHOW_USERGROUPS']

              uac_int = group_user[7][:value].to_i # Set this because it is used so frequently below
              sat_int = group_user[2][:value].to_i

              # Add the group to the database
              # Also parse the ADF_ flags from userAccountControl: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832(v=vs.85).aspx
              sql_param_user = { u_rid: user_rid,
                                 u_distinguishedName: group_user[0][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_sAMAccountType: group_user[2][:value].to_i,
                                 u_sAMAccountName: group_user[3][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_displayName: group_user[4][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_description: group_user[5][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_logonCount: group_user[6][:value].to_i,
                                 u_userAccountControl: uac_int,
                                 u_userPrincipalName: group_user[8][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_whenChanged: group_user[9][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_whenCreated: group_user[10][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_primaryGroupID: group_user[11][:value].to_i,
                                 u_badPwdCount: group_user[12][:value].to_i,
                                 u_comment: group_user[13][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_title: group_user[14][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 u_cn: group_user[15][:value].to_s.encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 # Indicates that a given object has had its ACLs changed to a more secure value by the
                                 # system because it was a member of one of the administrative groups (directly or transitively).
                                 u_adminCount: group_user[16][:value].to_i,
                                 u_manager: group_user[17][:value].to_s.encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                                 # The login script is executed
                                 u_ADS_UF_SCRIPT: (uac_int & 0x00000001).zero? ? 0 : 1,
                                 # The user account is disabled.
                                 u_ADS_UF_ACCOUNTDISABLE: (uac_int & 0x00000002).zero? ? 0 : 1,
                                 # The home directory is required.
                                 u_ADS_UF_HOMEDIR_REQUIRED: (uac_int & 0x00000008).zero? ? 0 : 1,
                                 # The account is currently locked out.
                                 u_ADS_UF_LOCKOUT: (uac_int & 0x00000010).zero? ? 0 : 1,
                                 # No password is required.
                                 u_ADS_UF_PASSWD_NOTREQD: (uac_int & 0x00000020).zero? ? 0 : 1,
                                 # The user cannot change the password.
                                 u_ADS_UF_PASSWD_CANT_CHANGE: (uac_int & 0x00000040).zero? ? 0 : 1,
                                 # The user can send an encrypted password.
                                 u_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: (uac_int & 0x00000080).zero? ? 0 : 1,
                                 # This is an account for users whose primary account is in another domain. This account
                                 # provides user access to this domain, but not to any domain that trusts this domain.
                                 # Also known as a local user account.
                                 u_ADS_UF_TEMP_DUPLICATE_ACCOUNT: (uac_int & 0x00000100).zero? ? 0 : 1,
                                 # This is a default account type that represents a typical user.
                                 u_ADS_UF_NORMAL_ACCOUNT: (uac_int & 0x00000200).zero? ? 0 : 1,
                                 # This is a permit to trust account for a system domain that trusts other domains.
                                 u_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT: (uac_int & 0x00000800).zero? ? 0 : 1,
                                 # This is a computer account for a computer that is a member of this domain.
                                 u_ADS_UF_WORKSTATION_TRUST_ACCOUNT: (uac_int & 0x00001000).zero? ? 0 : 1,
                                 # This is a computer account for a system backup domain controller that is a member of this domain.
                                 u_ADS_UF_SERVER_TRUST_ACCOUNT: (uac_int & 0x00002000).zero? ? 0 : 1,
                                 # The password for this account will never expire.
                                 u_ADS_UF_DONT_EXPIRE_PASSWD: (uac_int & 0x00010000).zero? ? 0 : 1,
                                 # This is an MNS logon account.
                                 u_ADS_UF_MNS_LOGON_ACCOUNT: (uac_int & 0x00020000).zero? ? 0 : 1,
                                 # The user must log on using a smart card.
                                 u_ADS_UF_SMARTCARD_REQUIRED: (uac_int & 0x00040000).zero? ? 0 : 1,
                                 # The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
                                 # Any such service can impersonate a client requesting the service.
                                 u_ADS_UF_TRUSTED_FOR_DELEGATION: (uac_int & 0x00080000).zero? ? 0 : 1,
                                 # The security context of the user will not be delegated to a service even if the service
                                 # account is set as trusted for Kerberos delegation.
                                 u_ADS_UF_NOT_DELEGATED: (uac_int & 0x00100000).zero? ? 0 : 1,
                                 # Restrict this principal to use only Data #Encryption Standard (DES) encryption types for keys.
                                 u_ADS_UF_USE_DES_KEY_ONLY: (uac_int & 0x00200000).zero? ? 0 : 1,
                                 # This account does not require Kerberos pre-authentication for logon.
                                 u_ADS_UF_DONT_REQUIRE_PREAUTH: (uac_int & 0x00400000).zero? ? 0 : 1,
                                 # The password has expired
                                 u_ADS_UF_PASSWORD_EXPIRED: (uac_int & 0x00800000).zero? ? 0 : 1,
                                 # The account is enabled for delegation. This is a security-sensitive setting; accounts with
                                 # this option enabled should be strictly controlled. This setting enables a service running
                                 # under the account to assume a client identity and authenticate as that user to other remote
                                 # servers on the network.
                                 u_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: (uac_int & 0x01000000).zero? ? 0 : 1,
                                 # Now add sAMAccountType constants
                                 u_SAM_DOMAIN_OBJECT: (sat_int == 0) ? 1 : 0,
                                 u_SAM_GROUP_OBJECT: (sat_int == 0x10000000) ? 1 : 0,
                                 u_SAM_NON_SECURITY_GROUP_OBJECT: (sat_int == 0x10000001) ? 1 : 0,
                                 u_SAM_ALIAS_OBJECT: (sat_int == 0x20000000) ? 1 : 0,
                                 u_SAM_NON_SECURITY_ALIAS_OBJECT: (sat_int == 0x20000001) ? 1 : 0,
                                 u_SAM_NORMAL_USER_ACCOUNT: (sat_int == 0x30000000) ? 1 : 0,
                                 u_SAM_MACHINE_ACCOUNT: (sat_int == 0x30000001) ? 1 : 0,
                                 u_SAM_TRUST_ACCOUNT: (sat_int == 0x30000002) ? 1 : 0,
                                 u_SAM_APP_BASIC_GROUP: (sat_int == 0x40000000) ? 1 : 0,
                                 u_SAM_APP_QUERY_GROUP: (sat_int == 0x40000001) ? 1 : 0,
                                 u_SAM_ACCOUNT_TYPE_MAX: (sat_int == 0x7fffffff) ? 1 : 0
                               }
              run_sqlite_query(db, 'ad_users', sql_param_user)

              # Now associate the user with the group
              sql_param_mapping = { user_rid: user_rid,
                                    group_rid: group_rid
                                  }
              run_sqlite_query(db, 'ad_mapping', sql_param_mapping)
            end

          rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
            print_error("Error(Users): #{e.message}")
            next
          end
        end
      end
      group_gather.map(&:join)
    end

    vprint_status "Retrieving computers"
    begin
      computer_filter = '(objectClass=computer)'
      computer_fields = ['distinguishedName', 'objectSid', 'cn', 'dNSHostName', 'sAMAccountType', 'sAMAccountName', 'displayName', 'logonCount', 'userAccountControl', 'whenChanged', 'whenCreated', 'primaryGroupID', 'badPwdCount', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'description', 'comment']
      computers = query(computer_filter, max_search, computer_fields)

      computers[:results].each do |comp|
        computer_rid = get_rid(comp[1][:value]).to_i

        uac_int = comp[8][:value].to_i # Set this because it is used so frequently below
        sat_int = comp[4][:value].to_i

        # Add the group to the database
        # Also parse the ADF_ flags from userAccountControl: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832(v=vs.85).aspx
        # Note that userAccountControl is basically the same for a computer as a user; this is because a computer account is derived from a user account
        # (if you look at the objectClass for a computer account, it includes 'user') and, for efficiency, we should really store it all in one
        # table. However, the reality is that it will get annoying for users to have to remember to use the userAccountControl flags to work out whether
        # its a user or a computer and so, for convenience and ease of use, I have put them in completely separate tables.
        # Also add the sAMAccount type flags from https://msdn.microsoft.com/en-us/library/windows/desktop/ms679637(v=vs.85).aspx
        sql_param_computer = { c_rid: computer_rid,
                               c_distinguishedName: comp[0][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_cn: comp[2][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_dNSHostName: comp[3][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_sAMAccountType: sat_int,
                               c_sAMAccountName: comp[5][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_displayName: comp[6][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_logonCount: comp[7][:value].to_i,
                               c_userAccountControl: uac_int,
                               c_whenChanged: comp[9][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_whenCreated: comp[10][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_primaryGroupID: comp[11][:value].to_i,
                               c_badPwdCount: comp[12][:value].to_i,
                               c_operatingSystem: comp[13][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_operatingSystemServicePack: comp[14][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_operatingSystemVersion: comp[15][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_description: comp[16][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               c_comment: comp[17][:value].encode('UTF-16be', invalid: :replace, undef: :replace, replace: '?').encode('UTF-8', invalid: :replace, undef: :replace, replace: '?'),
                               # The login script is executed
                               c_ADS_UF_SCRIPT: (uac_int & 0x00000001).zero? ? 0 : 1,
                               # The user account is disabled.
                               c_ADS_UF_ACCOUNTDISABLE: (uac_int & 0x00000002).zero? ? 0 : 1,
                               # The home directory is required.
                               c_ADS_UF_HOMEDIR_REQUIRED: (uac_int & 0x00000008).zero? ? 0 : 1,
                               # The account is currently locked out.
                               c_ADS_UF_LOCKOUT: (uac_int & 0x00000010).zero? ? 0 : 1,
                               # No password is required.
                               c_ADS_UF_PASSWD_NOTREQD: (uac_int & 0x00000020).zero? ? 0 : 1,
                               # The user cannot change the password.
                               c_ADS_UF_PASSWD_CANT_CHANGE: (uac_int & 0x00000040).zero? ? 0 : 1,
                               # The user can send an encrypted password.
                               c_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: (uac_int & 0x00000080).zero? ? 0 : 1,
                               # This is an account for users whose primary account is in another domain. This account
                               # provides user access to this domain, but not to any domain that trusts this domain.
                               # Also known as a local user account.
                               c_ADS_UF_TEMP_DUPLICATE_ACCOUNT: (uac_int & 0x00000100).zero? ? 0 : 1,
                               # This is a default account type that represents a typical user.
                               c_ADS_UF_NORMAL_ACCOUNT: (uac_int & 0x00000200).zero? ? 0 : 1,
                               # This is a permit to trust account for a system domain that trusts other domains.
                               c_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT: (uac_int & 0x00000800).zero? ? 0 : 1,
                               # This is a computer account for a computer that is a member of this domain.
                               c_ADS_UF_WORKSTATION_TRUST_ACCOUNT: (uac_int & 0x00001000).zero? ? 0 : 1,
                               # This is a computer account for a system backup domain controller that is a member of this domain.
                               c_ADS_UF_SERVER_TRUST_ACCOUNT: (uac_int & 0x00002000).zero? ? 0 : 1,
                               # The password for this account will never expire.
                               c_ADS_UF_DONT_EXPIRE_PASSWD: (uac_int & 0x00010000).zero? ? 0 : 1,
                               # This is an MNS logon account.
                               c_ADS_UF_MNS_LOGON_ACCOUNT: (uac_int & 0x00020000).zero? ? 0 : 1,
                               # The user must log on using a smart card.
                               c_ADS_UF_SMARTCARD_REQUIRED: (uac_int & 0x00040000).zero? ? 0 : 1,
                               # The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
                               # Any such service can impersonate a client requesting the service.
                               c_ADS_UF_TRUSTED_FOR_DELEGATION: (uac_int & 0x00080000).zero? ? 0 : 1,
                               # The security context of the user will not be delegated to a service even if the service
                               # account is set as trusted for Kerberos delegation.
                               c_ADS_UF_NOT_DELEGATED: (uac_int & 0x00100000).zero? ? 0 : 1,
                               # Restrict this principal to use only Data #Encryption Standard (DES) encryption types for keys.
                               c_ADS_UF_USE_DES_KEY_ONLY: (uac_int & 0x00200000).zero? ? 0 : 1,
                               # This account does not require Kerberos pre-authentication for logon.
                               c_ADS_UF_DONT_REQUIRE_PREAUTH: (uac_int & 0x00400000).zero? ? 0 : 1,
                               # The password has expired
                               c_ADS_UF_PASSWORD_EXPIRED: (uac_int & 0x00800000).zero? ? 0 : 1,
                               # The account is enabled for delegation. This is a security-sensitive setting; accounts with
                               # this option enabled should be strictly controlled. This setting enables a service running
                               # under the account to assume a client identity and authenticate as that user to other remote
                               # servers on the network.
                               c_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: (uac_int & 0x01000000).zero? ? 0 : 1,
                               # Now add the sAMAccountType objects
                               c_SAM_DOMAIN_OBJECT: (sat_int == 0) ? 1 : 0,
                               c_SAM_GROUP_OBJECT: (sat_int == 0x10000000) ? 1 : 0,
                               c_SAM_NON_SECURITY_GROUP_OBJECT: (sat_int == 0x10000001) ? 1 : 0,
                               c_SAM_ALIAS_OBJECT: (sat_int == 0x20000000) ? 1 : 0,
                               c_SAM_NON_SECURITY_ALIAS_OBJECT: (sat_int == 0x20000001) ? 1 : 0,
                               c_SAM_NORMAL_USER_ACCOUNT: (sat_int == 0x30000000) ? 1 : 0,
                               c_SAM_MACHINE_ACCOUNT: (sat_int == 0x30000001) ? 1 : 0,
                               c_SAM_TRUST_ACCOUNT: (sat_int == 0x30000002) ? 1 : 0,
                               c_SAM_APP_BASIC_GROUP: (sat_int == 0x40000000) ? 1 : 0,
                               c_SAM_APP_QUERY_GROUP: (sat_int == 0x40000001) ? 1 : 0,
                               c_SAM_ACCOUNT_TYPE_MAX: (sat_int == 0x7fffffff) ? 1 : 0
                         }
        run_sqlite_query(db, 'ad_computers', sql_param_computer)
        print_line "Computer [#{sql_param_computer[:c_cn]}][#{sql_param_computer[:c_dNSHostName]}][#{sql_param_computer[:c_rid]}]" if datastore['SHOW_COMPUTERS']
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
      db.type_translation = true

      # Create the table for the AD Computers
      db.execute('DROP TABLE IF EXISTS ad_computers')
      sql_table_computers = 'CREATE TABLE ad_computers ('\
                           'c_rid INTEGER PRIMARY KEY NOT NULL,'\
                           'c_distinguishedName TEXT UNIQUE NOT NULL,'\
                           'c_cn TEXT,'\
                           'c_sAMAccountType INTEGER,'\
                           'c_sAMAccountName TEXT UNIQUE NOT NULL,'\
                           'c_dNSHostName TEXT,'\
                           'c_displayName TEXT,'\
                           'c_logonCount INTEGER,'\
                           'c_userAccountControl INTEGER,'\
                           'c_primaryGroupID INTEGER,'\
                           'c_badPwdCount INTEGER,'\
                           'c_description TEXT,'\
                           'c_comment TEXT,'\
                           'c_operatingSystem TEXT,'\
                           'c_operatingSystemServicePack TEXT,'\
                           'c_operatingSystemVersion TEXT,'\
                           'c_whenChanged TEXT,'\
                           'c_whenCreated TEXT,'\
                           'c_ADS_UF_SCRIPT INTEGER,'\
                           'c_ADS_UF_ACCOUNTDISABLE INTEGER,'\
                           'c_ADS_UF_HOMEDIR_REQUIRED INTEGER,'\
                           'c_ADS_UF_LOCKOUT INTEGER,'\
                           'c_ADS_UF_PASSWD_NOTREQD INTEGER,'\
                           'c_ADS_UF_PASSWD_CANT_CHANGE INTEGER,'\
                           'c_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED INTEGER,'\
                           'c_ADS_UF_TEMP_DUPLICATE_ACCOUNT INTEGER,'\
                           'c_ADS_UF_NORMAL_ACCOUNT INTEGER,'\
                           'c_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT INTEGER,'\
                           'c_ADS_UF_WORKSTATION_TRUST_ACCOUNT INTEGER,'\
                           'c_ADS_UF_SERVER_TRUST_ACCOUNT INTEGER,'\
                           'c_ADS_UF_DONT_EXPIRE_PASSWD INTEGER,'\
                           'c_ADS_UF_MNS_LOGON_ACCOUNT INTEGER,'\
                           'c_ADS_UF_SMARTCARD_REQUIRED INTEGER,'\
                           'c_ADS_UF_TRUSTED_FOR_DELEGATION INTEGER,'\
                           'c_ADS_UF_NOT_DELEGATED INTEGER,'\
                           'c_ADS_UF_USE_DES_KEY_ONLY INTEGER,'\
                           'c_ADS_UF_DONT_REQUIRE_PREAUTH INTEGER,'\
                           'c_ADS_UF_PASSWORD_EXPIRED INTEGER,'\
                           'c_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION INTEGER,'\
                           'c_SAM_DOMAIN_OBJECT INTEGER,'\
                           'c_SAM_GROUP_OBJECT INTEGER,'\
                           'c_SAM_NON_SECURITY_GROUP_OBJECT INTEGER,'\
                           'c_SAM_ALIAS_OBJECT INTEGER,'\
                           'c_SAM_NON_SECURITY_ALIAS_OBJECT INTEGER,'\
                           'c_SAM_NORMAL_USER_ACCOUNT INTEGER,'\
                           'c_SAM_MACHINE_ACCOUNT INTEGER,'\
                           'c_SAM_TRUST_ACCOUNT INTEGER,'\
                           'c_SAM_APP_BASIC_GROUP INTEGER,'\
                           'c_SAM_APP_QUERY_GROUP INTEGER,'\
                           'c_SAM_ACCOUNT_TYPE_MAX INTEGER)'
      db.execute(sql_table_computers)

      # Create the table for the AD Groups
      db.execute('DROP TABLE IF EXISTS ad_groups')
      sql_table_group = 'CREATE TABLE ad_groups ('\
                           'g_rid INTEGER PRIMARY KEY NOT NULL,'\
                           'g_distinguishedName TEXT UNIQUE NOT NULL,'\
                           'g_sAMAccountType INTEGER,'\
                           'g_sAMAccountName TEXT UNIQUE NOT NULL,'\
                           'g_groupType INTEGER,'\
                           'g_adminCount INTEGER,'\
                           'g_description TEXT,'\
                           'g_comment TEXT,'\
                           'g_cn TEXT,'\
                           'g_managedBy TEXT,'\
                           'g_whenChanged TEXT,'\
                           'g_whenCreated TEXT,'\
                           'g_GT_GROUP_CREATED_BY_SYSTEM INTEGER,'\
                           'g_GT_GROUP_SCOPE_GLOBAL INTEGER,'\
                           'g_GT_GROUP_SCOPE_LOCAL INTEGER,'\
                           'g_GT_GROUP_SCOPE_UNIVERSAL INTEGER,'\
                           'g_GT_GROUP_SAM_APP_BASIC INTEGER,'\
                           'g_GT_GROUP_SAM_APP_QUERY INTEGER,'\
                           'g_GT_GROUP_SECURITY INTEGER,'\
                           'g_GT_GROUP_DISTRIBUTION INTEGER,'\
                           'g_SAM_DOMAIN_OBJECT INTEGER,'\
                           'g_SAM_GROUP_OBJECT INTEGER,'\
                           'g_SAM_NON_SECURITY_GROUP_OBJECT INTEGER,'\
                           'g_SAM_ALIAS_OBJECT INTEGER,'\
                           'g_SAM_NON_SECURITY_ALIAS_OBJECT INTEGER,'\
                           'g_SAM_NORMAL_USER_ACCOUNT INTEGER,'\
                           'g_SAM_MACHINE_ACCOUNT INTEGER,'\
                           'g_SAM_TRUST_ACCOUNT INTEGER,'\
                           'g_SAM_APP_BASIC_GROUP INTEGER,'\
                           'g_SAM_APP_QUERY_GROUP INTEGER,'\
                           'g_SAM_ACCOUNT_TYPE_MAX INTEGER)'
      db.execute(sql_table_group)

      # Create the table for the AD Users
      db.execute('DROP TABLE IF EXISTS ad_users')
      sql_table_users = 'CREATE TABLE ad_users ('\
                           'u_rid INTEGER PRIMARY KEY NOT NULL,'\
                           'u_distinguishedName TEXT UNIQUE NOT NULL,'\
                           'u_description TEXT,'\
                           'u_displayName TEXT,'\
                           'u_sAMAccountType INTEGER,'\
                           'u_sAMAccountName TEXT,'\
                           'u_logonCount INTEGER,'\
                           'u_userAccountControl INTEGER,'\
                           'u_primaryGroupID INTEGER,'\
                           'u_cn TEXT,'\
                           'u_adminCount INTEGER,'\
                           'u_badPwdCount INTEGER,'\
                           'u_userPrincipalName TEXT UNIQUE,'\
                           'u_comment TEXT,'\
                           'u_title TEXT,'\
                           'u_manager TEXT,'\
                           'u_whenCreated TEXT,'\
                           'u_whenChanged TEXT,'\
                           'u_ADS_UF_SCRIPT INTEGER,'\
                           'u_ADS_UF_ACCOUNTDISABLE INTEGER,'\
                           'u_ADS_UF_HOMEDIR_REQUIRED INTEGER,'\
                           'u_ADS_UF_LOCKOUT INTEGER,'\
                           'u_ADS_UF_PASSWD_NOTREQD INTEGER,'\
                           'u_ADS_UF_PASSWD_CANT_CHANGE INTEGER,'\
                           'u_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED INTEGER,'\
                           'u_ADS_UF_TEMP_DUPLICATE_ACCOUNT INTEGER,'\
                           'u_ADS_UF_NORMAL_ACCOUNT INTEGER,'\
                           'u_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT INTEGER,'\
                           'u_ADS_UF_WORKSTATION_TRUST_ACCOUNT INTEGER,'\
                           'u_ADS_UF_SERVER_TRUST_ACCOUNT INTEGER,'\
                           'u_ADS_UF_DONT_EXPIRE_PASSWD INTEGER,'\
                           'u_ADS_UF_MNS_LOGON_ACCOUNT INTEGER,'\
                           'u_ADS_UF_SMARTCARD_REQUIRED INTEGER,'\
                           'u_ADS_UF_TRUSTED_FOR_DELEGATION INTEGER,'\
                           'u_ADS_UF_NOT_DELEGATED INTEGER,'\
                           'u_ADS_UF_USE_DES_KEY_ONLY INTEGER,'\
                           'u_ADS_UF_DONT_REQUIRE_PREAUTH INTEGER,'\
                           'u_ADS_UF_PASSWORD_EXPIRED INTEGER,'\
                           'u_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION INTEGER,'\
                           'u_SAM_DOMAIN_OBJECT INTEGER,'\
                           'u_SAM_GROUP_OBJECT INTEGER,'\
                           'u_SAM_NON_SECURITY_GROUP_OBJECT INTEGER,'\
                           'u_SAM_ALIAS_OBJECT INTEGER,'\
                           'u_SAM_NON_SECURITY_ALIAS_OBJECT INTEGER,'\
                           'u_SAM_NORMAL_USER_ACCOUNT INTEGER,'\
                           'u_SAM_MACHINE_ACCOUNT INTEGER,'\
                           'u_SAM_TRUST_ACCOUNT INTEGER,'\
                           'u_SAM_APP_BASIC_GROUP INTEGER,'\
                           'u_SAM_APP_QUERY_GROUP INTEGER,'\
                           'u_SAM_ACCOUNT_TYPE_MAX INTEGER)'
      db.execute(sql_table_users)

      # Create the table for the mapping between the two (membership)
      db.execute('DROP TABLE IF EXISTS ad_mapping')
      sql_table_mapping = 'CREATE TABLE ad_mapping ('\
                           'user_rid INTEGER NOT NULL,' \
                           'group_rid INTEGER NOT NULL,'\
                           'PRIMARY KEY (user_rid, group_rid),'\
                           'FOREIGN KEY(user_rid) REFERENCES ad_users(u_rid)'\
                           'FOREIGN KEY(group_rid) REFERENCES ad_groups(g_rid))'
      db.execute(sql_table_mapping)

      # Create the view for the AD User/Group membership
      db.execute('DROP VIEW IF EXISTS view_mapping')
      sql_view_mapping = 'CREATE VIEW view_mapping AS SELECT ad_groups.*,ad_users.* FROM ad_mapping '\
                         'INNER JOIN ad_groups ON ad_groups.g_rid = ad_mapping.group_rid '\
                         'INNER JOIN ad_users ON ad_users.u_rid = ad_mapping.user_rid'
      db.execute(sql_view_mapping)

      return db, filename

    rescue SQLite3::Exception => e
      print_error("Error(Database): #{e.message}")
      return
    end
  end

  def get_rid(data)
    sid = data.unpack("bbbbbbbbV*")[8..-1]
    sid[-1]
  end
end
