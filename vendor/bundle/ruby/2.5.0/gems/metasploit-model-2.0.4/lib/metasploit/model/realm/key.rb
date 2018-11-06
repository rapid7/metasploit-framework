# Canonical `Metasploit::Credential::Realm#key`s.
#
# `Metasploit::Credential::Realm#key` is restricted to values in {ALL}, so new valid values need to be added to this
# module:
#
# 1. Add a String constant where the constant name is in SCREAMING_SNAKE_CASE and the String in Title Case.
# 2. Add the new constant to {ALL}.
# 3. Add a new key/value to {SHORT_NAMES} for this constant.
module Metasploit::Model::Realm::Key
  #
  # CONSTANTS
  #

  # An Active Directory domain that is used for authenication in Windows environments.
  #
  # @see https://en.wikipedia.org/wiki/Active_Directory
  ACTIVE_DIRECTORY_DOMAIN = 'Active Directory Domain'

  # A DB2 database name. Like PostgreSQL, DB2 requires a database to authenticate to.
  DB2_DATABASE = 'DB2 Database'

  # A System Identifier for an Oracle Database.
  #
  # @see http://docs.oracle.com/cd/E11882_01/server.112/e40540/startup.htm#CNCPT89037
  ORACLE_SYSTEM_IDENTIFIER = 'Oracle System Identifier'

  # A PostgreSQL database name.  Unlike, MySQL, PostgreSQL requires the user to authenticate to a specific
  # database and does not allow authenticating to just a server (which would be an `Mdm::Service`).
  POSTGRESQL_DATABASE = 'PostgreSQL Database'

  # An RSYNC module (share) name, which can optionally require authentication.
  RSYNC_MODULE = 'RSYNC Module'

  # This is a Wildcard Realm Type which indicates we don't know or care what type of Realm it is.
  WILDCARD = '*'

  # All values that are valid for {Metasploit::Credential::Realm#key}.
  ALL = [
    ACTIVE_DIRECTORY_DOMAIN,
    DB2_DATABASE,
    ORACLE_SYSTEM_IDENTIFIER,
    POSTGRESQL_DATABASE,
    RSYNC_MODULE,
    WILDCARD
  ]

  # A map of short names, suitable for use on the command line, to the
  # full human-readable constants above.
  SHORT_NAMES = {
    'domain'   => ACTIVE_DIRECTORY_DOMAIN,
    'db2db'    => DB2_DATABASE,
    'sid'      => ORACLE_SYSTEM_IDENTIFIER,
    'pgdb'     => POSTGRESQL_DATABASE,
    'rsync'    => RSYNC_MODULE,
    'wildcard' => WILDCARD
  }
end
