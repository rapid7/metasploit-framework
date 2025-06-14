## Introduction

This is a post exploitation module which has the effect of copying the AD groups, user membership
(taking into account nested groups), user information and computers to a local SQLite database.
This is particularly useful for red teaming and simulated attack engagements because it offers
the ability to gain situational awareness of the target's domain completely offline. Examples of
queries that can be run locally include:

* Identification of members in a particular group (e.g. 'Domain Admins'), taking into account
  members of nested groups.
* Organizational hierarchy information (if the manager LDAP attribute is used).
* Ability to determine group membership and user membership (e.g. 'What groups are these users a
  member of?', 'What users are members of these groups?', 'List all members who are effectively
  members of the Domain Admins group who are not disabled' etc)
* Expansion of the userAccountControl and sAMAccountType variables for querying ease.
* Generation of a list of DNS hostnames, computer names, operating system versions etc of each
  domain joined computer.
* Identification of security groups that have managers.
* Exporting anything above in different formats, including those which can be imported into
  other tools.

## Mechanism

This module makes heavy usage of ADSI and performs the following basic steps:

**User and group acquisition**

* Perform an ADSI query to list all active directory groups and store them in the local ad_groups
  table (parsing attributes which contain flags).
* Loop through them and, for each group, launch another LDAP query to list the effective members of
  the group (using the LDAP_MATCHING_RULE_IN_CHAIN OID). The effect is that it will reveal all
  effective members of that group, even if they are not direct members of the group.
* For each user, perform another query to obtain user specific attributes and insert them into the
  local ad_users table.
* Insert a new row into the ad_mapping table associating the user RID with the group RID.

**Computer acquisition**

* Perform an ADSI query to list all computers in the domain.
* Parse any attributes containing flags (userAccountControl, sAMAccountType) and insert them into
  the local ad_computers table.

## Module Specific Options

Option          | Purpose
--------------- | --------
GROUP_FILTER    | Additional LDAP filters to apply when building the initial list of groups.
SHOW_COMPUTERS  | If set to TRUE, this will write a line-by-line list of computers, in the format: ```Computer [Name][DNS][RID]``` to the console. For example: ```Computer [W2K8DC][W2K8DC.goat.stu][1000]```
SHOW_USERGROUPS | If set to TRUE, this will write a line-by-line list of user to group memberships, in the format: ```Group [Group Name][Group RID] has member [Username][User RID]```. For example: ```Group [Domain Users][513] has member [it.director][1132]```. This can be used mainly for progress, but it may be simpler to cat and grep for basic queries. However, the real power of this module comes from the ability to rapidly perform queries against the SQLite database.

## SQLite Database

**Construction**

The following tables will be present in the local SQLite database. The ad_* tables use the RID of
the user, computer or group as the primary key, and the view_mapping table effectively joins the
ad_mapping table with ad_users.* and ad_groups.* by RID.

Note that the purpose of the less obvious flags is documented in the source code, along with
references to MSDN and Technet where appropriate, so this can be easily looked up during an
engagement without needing to refer to this page.

Table Name   | Purpose
------------ | --------
ad_computers | Information on each of the domain joined computers.
ad_users     | Information on each of the domain users.
ad_groups    | Information on each of the active directory groups.
ad_mapping   | Links the users table to the groups table (i.e. can be used to show which users are effectively members of which groups).
view_mapping | Joins the ad_mapping table to the ad_users and ad_groups table, provided for convenience. This will be the table that most queries will be run against.

Within each table, the naming convention for the columns is to prefix anything in the
ad_computers table with c_, anything in the ad_users table with u_ and anything in the
ad_groups table with g_. This convention makes the joins between tables much more intuitive.

**ad_computers**

The table below shows the columns in the ad_computers table. The fields in capitals at the end
(c_ADS_* and c_SAM_*) are expanded from the userAccountControl and sAMAccountType attributes to
provide an easy way to perform the queries against individual flags.

Column Name                                      | Type    | Purpose
------------------------------------------------ | ------- | --------
c_rid                                            | INTEGER | The relative identifier which is derived from the objectSid (i.e. the last group of digits).
c_distinguishedName                              | TEXT    | The main 'fully qualified' reference to the object. See [Distinguished Names](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366101%28v=vs.85%29.aspx).
c_cn                                             | TEXT    | The name that represents an object. Used to perform searches.
c_sAMAccountType                                 | INTEGER | This attribute contains information about every account type object. As this can only have one value, it would be more efficient to implement a lookup table for this, but I have included individual flags simply for consistency.
c_sAMAccountName                                 | TEXT    | The logon name used to support clients and servers running earlier versions of the operating system.
c_dNSHostName                                    | TEXT    | The name of computer, as registered in DNS.
c_displayName                                    | TEXT    | The display name for an object. This is usually the combination of the users first name, middle initial, and last name.
c_logonCount                                     | INTEGER | The number of times the account has successfully logged on. A value of 0 indicates that the value is unknown.
c_userAccountControl                             | INTEGER | Flags that control the behavior of the user account. See [Use-Account-Control attribute](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832%28v=vs.85%29.aspx) for a description, but they are also parsed and stored in the c_ADS_UF_* columns below.
c_primaryGroupID                                 | INTEGER | Contains the relative identifier (RID) for the primary group of the user. By default, this is the RID for the Domain Users group.
c_badPwdCount                                    | INTEGER | The number of times the user tried to log on to the account using an incorrect password. A value of 0 indicates that the value is unknown.
c_description                                    | TEXT    | Contains the description to display for an object.
c_comment                                        | TEXT    | The user's comment. This string can be a null string. Sometimes passwords or sensitive information can be stored here.
c_operatingSystem                                | TEXT    | The Operating System name, for example, Windows Vista Enterprise.
c_operatingSystemServicePack                     | TEXT    | The operating system service pack ID string (for example, SP3).
c_operatingSystemVersion                         | TEXT    | The operating system version string, for example, 4.0.
c_whenChanged                                    | TEXT    | The date when this object was last changed. This value is not replicated and exists in the global catalog.
c_whenCreated                                    | TEXT    | The date when this object was created. This value is replicated and is in the global catalog.
c_ADS_UF_SCRIPT                                  | INTEGER | If 1, the logon script is executed.
c_ADS_UF_ACCOUNTDISABLE                          | INTEGER | If 1, the user account is disabled.
c_ADS_UF_HOMEDIR_REQUIRED                        | INTEGER | If 1, the home directory is required.
c_ADS_UF_LOCKOUT                                 | INTEGER | If 1, the account is currently locked out.
c_ADS_UF_PASSWD_NOTREQD                          | INTEGER | If 1, no password is required.
c_ADS_UF_PASSWD_CANT_CHANGE                      | INTEGER | If 1, the user cannot change the password. 
c_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED         | INTEGER | If 1, the user can send an encrypted password.
c_ADS_UF_TEMP_DUPLICATE_ACCOUNT                  | INTEGER | If 1, this is an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. Also known as a local user account.
c_ADS_UF_NORMAL_ACCOUNT                          | INTEGER | If 1, this is a default account type that represents a typical user.
c_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT               | INTEGER | If 1, this is a permit to trust account for a system domain that trusts other domains.
c_ADS_UF_WORKSTATION_TRUST_ACCOUNT               | INTEGER | If 1, this is a computer account for a computer that is a member of this domain.
c_ADS_UF_SERVER_TRUST_ACCOUNT                    | INTEGER | If 1, this is a computer account for a system backup domain controller that is a member of this domain.
c_ADS_UF_DONT_EXPIRE_PASSWD                      | INTEGER | If 1, the password for this account will never expire.
c_ADS_UF_MNS_LOGON_ACCOUNT                       | INTEGER | If 1, this is an MNS logon account.
c_ADS_UF_SMARTCARD_REQUIRED                      | INTEGER | If 1, the user must log on using a smart card.
c_ADS_UF_TRUSTED_FOR_DELEGATION                  | INTEGER | If 1, the service account (user or computer account), under which a service runs, is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service.
c_ADS_UF_NOT_DELEGATED                           | INTEGER | If 1, the security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation.
c_ADS_UF_USE_DES_KEY_ONLY                        | INTEGER | If 1, restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
c_ADS_UF_DONT_REQUIRE_PREAUTH                    | INTEGER | If 1, this account does not require Kerberos pre-authentication for logon.
c_ADS_UF_PASSWORD_EXPIRED                        | INTEGER | If 1, the user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the domain policy.
c_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION  | INTEGER | If 1, the account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled should be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate as that user to other remote servers on the network.
c_SAM_DOMAIN_OBJECT                              | INTEGER | See [SAM-Account-Type](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679637%28v=vs.85%29.aspx) attribute. If 1, this flag is set.
c_SAM_GROUP_OBJECT                               | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_NON_SECURITY_GROUP_OBJECT                  | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_ALIAS_OBJECT                               | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_NON_SECURITY_ALIAS_OBJECT                  | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_USER_OBJECT                                | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_NORMAL_USER_ACCOUNT                        | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_MACHINE_ACCOUNT                            | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_TRUST_ACCOUNT                              | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_APP_BASIC_GROUP                            | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_APP_QUERY_GROUP                            | INTEGER | If 1, this flag is set (sAMAccountType attribute).
c_SAM_ACCOUNT_TYPE_MAX                           | INTEGER | If 1, this flag is set (sAMAccountType attribute).

**ad_users**

The table below shows the columns in the ad_computers table. The fields in capitals at the end
(c_ADS_* and c_SAM_*) are expanded from the userAccountControl and sAMAccountType attributes to
provide an easy way to perform the queries against individual flags.

Column Name                                     | Type    | Purpose
------------------------------------------------| ------- | -------
u_rid                                           | INTEGER | The relative identifier which is derived from the objectSid (i.e. the last group of digits).
u_distinguishedName                             | TEXT    | The main 'fully qualified' reference to the object. See [Distinguished Names](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366101%28v=vs.85%29.aspx).
u_cn                                            | TEXT    | The name that represents an object. Used to perform searches.
u_sAMAccountType                                | INTEGER | This attribute contains information about every account type object. As this can only have one value, it would be more efficient to implement a lookup table for this, but I have included individual flags simply for consistency.
u_sAMAccountName                                | TEXT    | The logon name used to support clients and servers running earlier versions of the operating system.
u_dNSHostName                                   | TEXT    | The name of computer, as registered in DNS.
u_displayName                                   | TEXT    | The display name for an object. This is usually the combination of the users first name, middle initial, and last name.
u_logonCount                                    | INTEGER | The number of times the account has successfully logged on. A value of 0 indicates that the value is unknown.
u_userPrincipalName                             | TEXT    | Technically, this is an Internet-style login name for a user based on the Internet standard RFC 822. By convention and in practice, it is the user's e-mail address.
u_displayName                                   | TEXT    | N/A
u_adminCount                                    | INTEGER | Indicates that a given object has had its ACLs changed to a more secure value by the system because it was a member of one of the administrative groups (directly or transitively).
u_userAccountControl                            | INTEGER | Flags that control the behavior of the user account. See [User-Account-Control](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680832%28v=vs.85%29.aspx) for a description, but they are also parsed and stored in the c_ADS_UF_* columns below.
u_primaryGroupID                                | INTEGER | Contains the relative identifier (RID) for the primary group of the user. By default, this is the RID for the Domain Users group.
u_badPwdCount                                   | INTEGER | The number of times the user tried to log on to the account using an incorrect password. A value of 0 indicates that the value is unknown.
u_description                                   | TEXT    | Contains the description to display for an object.
u_title                                         | TEXT    | Contains the user's job title. This property is commonly used to indicate the formal job title, such as Senior Programmer, rather than occupational class.
u_manager                                       | TEXT    | The distinguished name of this user's manager.
u_comment                                       | TEXT    | The user's comment. This string can be a null string. Sometimes passwords or sensitive information can be stored here.
u_whenChanged                                   | TEXT    | The date when this object was last changed. This value is not replicated and exists in the global catalog.
u_whenCreated                                   | TEXT    | The date when this object was created. This value is replicated and is in the global catalog.
u_ADS_UF_SCRIPT                                 | INTEGER | If 1, the logon script is executed.
u_ADS_UF_ACCOUNTDISABLE                         | INTEGER | If 1, the user account is disabled.
u_ADS_UF_HOMEDIR_REQUIRED                       | INTEGER | If 1, the home directory is required.
u_ADS_UF_LOCKOUT                                | INTEGER | If 1, the account is currently locked out.
u_ADS_UF_PASSWD_NOTREQD                         | INTEGER | If 1, no password is required.
u_ADS_UF_PASSWD_CANT_CHANGE                     | INTEGER | If 1, the user cannot change the password. 
u_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED        | INTEGER | If 1, the user can send an encrypted password.
u_ADS_UF_TEMP_DUPLICATE_ACCOUNT                 | INTEGER | If 1, this is an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. Also known as a local user account.
u_ADS_UF_NORMAL_ACCOUNT                         | INTEGER | If 1, this is a default account type that represents a typical user.
u_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT              | INTEGER | If 1, this is a permit to trust account for a system domain that trusts other domains.
u_ADS_UF_WORKSTATION_TRUST_ACCOUNT              | INTEGER | If 1, this is a computer account for a computer that is a member of this domain.
u_ADS_UF_SERVER_TRUST_ACCOUNT                   | INTEGER | If 1, this is a computer account for a system backup domain controller that is a member of this domain.
u_ADS_UF_DONT_EXPIRE_PASSWD                     | INTEGER | If 1, the password for this account will never expire.
u_ADS_UF_MNS_LOGON_ACCOUNT                      | INTEGER | If 1, this is an MNS logon account.
u_ADS_UF_SMARTCARD_REQUIRED                     | INTEGER | If 1, the user must log on using a smart card.
u_ADS_UF_TRUSTED_FOR_DELEGATION                 | INTEGER | If 1, the service account (user or computer account), under which a service runs, is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service.
u_ADS_UF_NOT_DELEGATED                          | INTEGER | If 1, the security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation.
u_ADS_UF_USE_DES_KEY_ONLY                       | INTEGER | If 1, restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
u_ADS_UF_DONT_REQUIRE_PREAUTH                   | INTEGER | If 1, this account does not require Kerberos pre-authentication for logon.
u_ADS_UF_PASSWORD_EXPIRED                       | INTEGER | If 1, the user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the domain policy.
u_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION | INTEGER | If 1, the account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled should be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate as that user to other remote servers on the network.
u_SAM_DOMAIN_OBJECT                             | INTEGER | See [SAM-Account-Type](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679637%28v=vs.85%29.aspx). If 1, this flag is set.
u_SAM_GROUP_OBJECT                              | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_NON_SECURITY_GROUP_OBJECT                 | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_ALIAS_OBJECT                              | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_NON_SECURITY_ALIAS_OBJECT                 | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_USER_OBJECT                               | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_NORMAL_USER_ACCOUNT                       | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_MACHINE_ACCOUNT                           | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_TRUST_ACCOUNT                             | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_APP_BASIC_GROUP                           | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_APP_QUERY_GROUP                           | INTEGER | If 1, this flag is set (sAMAccountType attribute).
u_SAM_ACCOUNT_TYPE_MAX                          | INTEGER | If 1, this flag is set (sAMAccountType attribute).

**ad_groups**

The table below shows the columns in the ad_groups table. 

Column Name                     | Type    | Purpose
--------------------------------| ------- | -------
g_rid                           | INTEGER | The relative identifier which is derived from the objectSid (i.e. the last group of digits).
g_distinguishedName             | TEXT    | The main 'fully qualified' reference to the object. See [Distinguished Names](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366101%28v=vs.85%29.aspx).
g_sAMAccountType                | INTEGER | This attribute contains information about every account type object. As this can only have one value, it would be more efficient to implement a lookup table for this, but I have included individual flags simply for consistency.
g_sAMAccountName                | TEXT    | The logon name used to support clients and servers running earlier versions of the operating system.
g_adminCount                    | INTEGER | Indicates that a given object has had its ACLs changed to a more secure value by the system because it was a member of one of the administrative groups (directly or transitively).
g_description                   | TEXT    | Contains the description to display for an object.
g_comment                       | TEXT    | The user's comment. This string can be a null string. Sometimes passwords or sensitive information can be stored here.
g_whenChanged                   | TEXT    | The date when this object was last changed. This value is not replicated and exists in the global catalog.
g_whenCreated                   | TEXT    | The date when this object was created. This value is replicated and is in the global catalog.
g_managedby                     | TEXT    | The manager of this group.
g_cn                            | TEXT    | The common name of the group.
g_groupType                     | INTEGER | Contains a set of flags that define the type and scope of a group object. These are expanded in the g_GT_* fields below.
g_GT_GROUP_CREATED_BY_SYSTEM    | INTEGER | If 1, this is a group that is created by the system.
g_GT_GROUP_SCOPE_GLOBAL         | INTEGER | If 1, this is a group with global scope.
g_GT_GROUP_SCOPE_LOCAL          | INTEGER | If 1, this is a group with domain local scope.
g_GT_GROUP_SCOPE_UNIVERSAL      | INTEGER | If 1, this is a group with universal scope.
g_GT_GROUP_SAM_APP_BASIC        | INTEGER | If 1, this specifies an APP_BASIC group for Windows Server Authorisation Manager.
g_GT_GROUP_SAM_APP_QUERY        | INTEGER | If 1, this specifies an APP_QUERY group for Windows Server Authorisation Manager.
g_GT_GROUP_SECURITY             | INTEGER | If 1, this specifies a security group.
g_GT_GROUP_DISTRIBUTION         | INTEGER | If 1, this specifies a distribution group (this is the inverse of g_GT_GROUP_SECURITY). I have included it so that distribution groups can be identified more easily (query readability).
g_SAM_DOMAIN_OBJECT             | INTEGER | See [SAM-Account-Type](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679637%28v=vs.85%29.aspx). If 1, this flag is set.
g_SAM_GROUP_OBJECT              | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_NON_SECURITY_GROUP_OBJECT | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_ALIAS_OBJECT              | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_NON_SECURITY_ALIAS_OBJECT | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_USER_OBJECT               | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_NORMAL_USER_ACCOUNT       | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_MACHINE_ACCOUNT           | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_TRUST_ACCOUNT             | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_APP_BASIC_GROUP           | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_APP_QUERY_GROUP           | INTEGER | If 1, this flag is set (sAMAccountType attribute).
g_SAM_ACCOUNT_TYPE_MAX          | INTEGER | If 1, this flag is set (sAMAccountType attribute).

**ad_mapping**

The table below shows the columns in the ad_mapping table. This is used to link users to groups. 

Column Name | Type    | Purpose
------------| ------- | -------
user_rid    | INTEGER | The RID of a user
group_rid   | INTEGER | The RID of a group

For example, if a particular record had a user_rid of 1000 and a group_rid of 1001, this would
imply that the user whose RID is 1000 is a member of the group whose RID is 1001. Use the
view_mapping view in order to do any meaningful queries, but its content is derived from this one.

**view_mapping**

This table is a combination of ad_groups.* and ad_users.*. Therefore, the fields are the
combination of the u_* and the g_* fields shown above.

## Database Structure

There are a few design choices that I have deliberately made which I have given an explanation for
below. This is because the reasons for them may not be obvious.

The users, groups and computers are based on the same class, so the "proper" way to do this would
be to place them all into one table and then restrict results based on sAMAccountType to determine
what type of object it is. In addition, the userAccountControl and sAMAccountType and groupType
attributes have been split out into individual columns which is, from a technical point of view,
unnecessary duplication.

The reason for this is ease of use; we are much more intuitively familiar with users, groups and
computers being different objects (even if they are all really the same thing), and it is much
easier to understand and formulate a query such as:

```
SELECT u_sAMAccountName from ad_users where u_ADS_UF_LOCKOUT = 0 and u_SAM_NORMAL_USER_ACCOUNT = 1
```

than:

```
SELECT u_sAMAccountName from ad_users where ((u_userAccountControl&0x00000010) = 0) and ((u_sAMAccountType&0x30000000) > 0)
```

This is also true of the sAMAccountType value; this is a code which has a 1:1 mapping with MSDN
constants (i.e. they are not flags) and it would be more efficient to implement a simple lookup table.
However, for consistency, I have implemented the columns for the possible values in the same way as
the attributes which comprise multiple values in the form of flags.

This database is designed for quick-and-dirty queries, not to be an efficient AD database, and the
benefits of the ease of access significantly outweighs the slight performance impact.

## Conversion to Unicode

All of the strings injected into the database have been converted to UTF-8 (encode('UTF-8')) which,
at first glance, does not seem necessary. The reason is documented [here](https://github.com/rails/rails/issues/1965);
namely that SQLite stores Unicode strings as 'text' but non-converted strings as 'blobs' regardless
of the type affinity. Omitting the unicode conversion meant that most of the text queries did not
work properly because the database was treating the text fields as raw binary data.

## Multi valued attributes

With the exception of the memberOf attribute, it is assumed that other attributes are single
valued, which may result in a small about of information being missed. For example, the
description attribute can (in some circumstances) be multi-valued but the ADSI queries will only
return the first value.

This will not make any practical difference for the vast majority of enterprise domains. 

## Database Queries

Sqlite3 supports a number of output formats (use .mode for all options). These can be used to
easily present the searched data.

For example, line mode is useful to see all fields in an easy to view form. The example query
searches for all information about the user whose username is 'unprivileged.user'

```
sqlite> .mode line
sqlite> select * from ad_users where u_sAMAccountName = "unprivileged.user";
                                          u_rid = 1127
                            u_distinguishedName = CN=Unprivileged User,CN=Users,DC=goat,DC=stu
                                  u_description = Do not delete. Default pass set to password123
                                  u_displayName = Unprivileged User
                               u_sAMAccountType = 805306368
                               u_sAMAccountName = unprivileged.user
                                   u_logonCount = 1
                           u_userAccountControl = 512
                               u_primaryGroupID = 513
                                           u_cn = Unprivileged User
                                   u_adminCount = 1
                                  u_badPwdCount = 0
                            u_userPrincipalName = unprivileged.user@goat.stu
                                      u_comment = 
                                        u_title = 
                                      u_manager = CN=Stuart Morgan - User,CN=Users,DC=goat,DC=stu
                                  u_whenCreated = 2015-12-20 20:10:54.000
                                  u_whenChanged = 2015-12-20 23:12:48.000
                                u_ADS_UF_SCRIPT = 0
                        u_ADS_UF_ACCOUNTDISABLE = 0
                      u_ADS_UF_HOMEDIR_REQUIRED = 0
                               u_ADS_UF_LOCKOUT = 0
                        u_ADS_UF_PASSWD_NOTREQD = 0
                    u_ADS_UF_PASSWD_CANT_CHANGE = 0
       u_ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0
                u_ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0
                        u_ADS_UF_NORMAL_ACCOUNT = 1
             u_ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0
             u_ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0
                  u_ADS_UF_SERVER_TRUST_ACCOUNT = 0
                    u_ADS_UF_DONT_EXPIRE_PASSWD = 0
                     u_ADS_UF_MNS_LOGON_ACCOUNT = 0
                    u_ADS_UF_SMARTCARD_REQUIRED = 0
                u_ADS_UF_TRUSTED_FOR_DELEGATION = 0
                         u_ADS_UF_NOT_DELEGATED = 0
                      u_ADS_UF_USE_DES_KEY_ONLY = 0
                  u_ADS_UF_DONT_REQUIRE_PREAUTH = 0
                      u_ADS_UF_PASSWORD_EXPIRED = 0
u_ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0
                            u_SAM_DOMAIN_OBJECT = 0
                             u_SAM_GROUP_OBJECT = 0
                u_SAM_NON_SECURITY_GROUP_OBJECT = 0
                             u_SAM_ALIAS_OBJECT = 0
                u_SAM_NON_SECURITY_ALIAS_OBJECT = 0
                      u_SAM_NORMAL_USER_ACCOUNT = 1
                          u_SAM_MACHINE_ACCOUNT = 0
                            u_SAM_TRUST_ACCOUNT = 0
                          u_SAM_APP_BASIC_GROUP = 0
                          u_SAM_APP_QUERY_GROUP = 0
                         u_SAM_ACCOUNT_TYPE_MAX = 0
```

SQLite can generate output in HTML format with headers. For example, the query below displays the
username, email address and number of times that the user has logged on for all users who have a
manager with the word 'Stuart' somewhere in the DN.

```
sqlite> .mode html
sqlite> .headers on                                   
sqlite> select u_sAMAccountName,u_userPrincipalName,u_logonCount from ad_users where u_manager LIKE '%Stuart%';
<TR><TH>u_sAMAccountName</TH>
<TH>u_userPrincipalName</TH>
<TH>u_logonCount</TH>
</TR>
<TR><TD>unprivileged.user</TD>
<TD>unprivileged.user@goat.stu</TD>
<TD>1</TD>
</TR>
sqlite> 
```

The same query can be used in INSERT mode, in which the results will be displayed as a series of
SQL insert statements for importing into another database:

```
sqlite> .mode insert
sqlite> select u_sAMAccountName,u_userPrincipalName,u_logonCount from ad_users where u_manager LIKE '%Stuart%';
INSERT INTO table(u_sAMAccountName,u_userPrincipalName,u_logonCount) VALUES('unprivileged.user','unprivileged.user@goat.stu',1);
```

The default mode (list) will display the results with a pipe character separating the fields:

```
sqlite> .mode list
sqlite> select u_sAMAccountName,u_userPrincipalName,u_logonCount from ad_users where u_manager LIKE '%Stuart%';
u_sAMAccountName u_userPrincipalName u_logonCount
unprivileged.user unprivileged.user@goat.stu 1
```

There are a number of other ways that this information could be presented; please play with SQLite
in order to learn how to use them.

## Example Queries

A number of example queries are shown below, in order to give an idea of how easy it is to build up
complex queries.

Search for all users who have a title, description or comment and display this information along
with their username:

```
select u_sAMAccountName,u_title,u_description,u_comment from ad_users where (u_title != "" or u_description != "" or u_comment != "");
```

Display all stored fields for all users whose accounts are not disabled, have a password that does
not expire, have a name starting with 'Frank' and have logged on more than once.

```
select * from ad_users where u_ADS_UF_ACCOUNTDISABLE=0 and u_ADS_UF_DONT_EXPIRE_PASSWD=1 and u_cn LIKE 'Frank%' and u_logonCount>1;
```

Get the list of group RIDs that have a name which do not have the word 'admin' in them somewhere
(perhaps useful to construct a golden ticket with access to pretty much all groups except anything
with 'admin' in it), might be useful to evade a very basic form of monitoring perhaps?

```
select DISTINCT g_rid from ad_groups where g_sAMAccountName NOT LIKE '%admin%';
```

Search for all users who are members of the 'Domain Admins' group and display their username.
Note that this will include those in nested groups.

```
select u_sAMAccountName from view_mapping where g_sAMAccountName = 'Domain Admins';
```

Show the groups that the user 'stufus' is a member of and write the output to /tmp/groups.txt
(e.g. for usage in a different tool):

```
.once /tmp/groups.txt
select g_sAMAccountName from view_mapping where u_sAMAccountName = 'stufus';
```

Imagine you have compromised passwords or accounts for user1, user2, user3 and user4. Show the AD
groups which, between them all, you have access to.

```
select DISTINCT g_sAMAccountName from view_mapping where u_sAMAccountName IN ('user1','user2','user3','user4');
```

Retrieve the list of group names common to both 'user1' and 'user2' and display the group RID,
group name and group description. This could be useful if you were aware that both these users
are in a group that has access to a very specific resource but are in a large number of separate
other groups.

```
select v1.g_rid,v1.g_sAMAccountName,v1.g_description FROM view_mapping v1 INNER JOIN view_mapping v2 ON v1.g_rid = v2.g_rid where v1.u_sAMAccountName = 'user1' and v2.u_sAMAccountName = 'user2';
```

Show the name, DNS hostname and OS information for each of the computers in the domain:

```
select c_cn,c_dNSHostName,c_operatingSystem,c_operatingSystemVersion,c_operatingSystemServicePack from ad_computers;
```

Display the same columns as above but only show machines in the 'Domain Controllers' OU (you can't
normally search by DN because it isn't a "real" attribute when querying through LDAP, but as it is
a normal text field in the database, you can use regular expressions and normal string matching):

```
select c_cn,c_dNSHostName,c_operatingSystem,c_operatingSystemVersion,c_operatingSystemServicePack from ad_computers where c_distinguishedName LIKE '%OU=Domain Controllers%';
```

Show all fields for computers that have the c_ADS_UF_WORKSTATION_TRUST_ACCOUNT set to 1 (which
seems to be everything except domain controllers) on my test system:

```
select * from ad_computers where c_ADS_UF_WORKSTATION_TRUST_ACCOUNT = 1;
```

Show all fields for computers whose operating system is Windows XP, Windows 2000 or Windows 2003
(note that you need regular expression support in SQLite):

```
select * from ad_computers where c_operatingSystem REGEXP '(XP|200[03])';
```

...and if you don't have regular expression support:

```
select * from ad_computers where c_operatingSystem LIKE '%XP%' OR c_operatingSystem LIKE '%2000%' OR c_operatingSystem LIKE '%2003%';
```

Search for all members of all groups who are (amongst other things) members of any group managed
by anyone whose CN starts with 'Unprivileged User' and return their username only:

```
select DISTINCT u_sAMAccountName from view_mapping where g_rid IN (select g_rid from view_mapping where g_managedBy LIKE 'CN=Unprivileged User%');
```

## Scenarios

**Group Policy Objects**

This cannot be used to gain a complete understanding of effective permissions because it does not
analyze group policy objects. For example, a group policy may add inconspicuous groups to
privileged groups and privileged groups, such as Domain Admins, may be removed from local
administrator groups due to GPP. Therefore, this will give a reliable overview of the effective
'static' permissions but cannot be completely relied on for overall effective permissions.

**Domain Controller interaction**

The acquisition of domain information does involve repeated queries against the domain controllers.
However, all interaction with AD uses native functionality and has not been noted to cause
performance problems when tested. This was recently tested on a live engagement on a domain that
has just under 11,000 groups and a similar number of users. Admittedly it took about an hour to
pull down everything (as opposed to the 1 minute to replicate the LDAP database) but the final
database size was 19,255,296 bytes, so perfectly manageable.
