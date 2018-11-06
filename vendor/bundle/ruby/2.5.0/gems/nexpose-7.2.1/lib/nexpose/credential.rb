module Nexpose

  # Contains the shared methods for the SiteCredential and SharedCredential Objects.
  # See Nexpose::SiteCredential or Nexpose::SharedCredential for additional info.
  class Credential < APIObject
    include Nexpose::CredentialHelper

    # Mapping of Common Ports.
    DEFAULT_PORTS = { 'cvs'              => 2401,
                      'ftp'              => 21,
                      'http'             => 80,
                      'as400'            => 449,
                      'notes'            => 1352,
                      'tds'              => 1433,
                      'sybase'           => 5000,
                      'cifs'             => 445,
                      'cifshash'         => 445,
                      'oracle'           => 1521,
                      'pop'              => 110,
                      'postgresql'       => 5432,
                      'remote execution' => 512,
                      'snmp'             => 161,
                      'snmpv3'           => 161,
                      'ssh'              => 22,
                      'ssh-key'          => 22,
                      'telnet'           => 23,
                      'mysql'            => 3306,
                      'db2'              => 50_000 }

    # Credential scope
    module Scope
      ALL_SITES_ENABLED_DEFAULT  = 'A'
      ALL_SITES_DISABLED_DEFAULT = 'G'
      SITE_SPECIFIC              = 'S'
    end

    # Credential Service/Type Options.
    module Service
      CVS              = 'cvs'              # Concurrent Versioning System (CVS)
      FTP              = 'ftp'              # File Transfer Protocol (FTP)
      HTTP             = 'http'             # Web Site HTTP Authentication
      AS400            = 'as400'            # IBM AS/400
      NOTES            = 'notes'            # Lotus Notes/Domino
      TDS              = 'tds'              # Microsoft SQL Server
      SYBASE           = 'sybase'           # Sybase SQL Server
      CIFS             = 'cifs'             # Microsoft Windows/Samba (SMB/CIFS)
      CIFSHASH         = 'cifshash'         # Microsoft Windows/Samba LM/NTLM Hash (SMB/CIFS)
      ORACLE           = 'oracle'           # Oracle
      POP              = 'pop'              # Post Office Protocol (POP)
      POSTGRESQL       = 'postgresql'       # PostgreSQL
      REMOTE_EXECUTION = 'remote execution' # Remote Execution
      SNMP             = 'snmp'             # Simple Network Management Protocol
      SNMPV3           = 'snmpv3'           # Simple Network Management Protocol v3
      SSH              = 'ssh'              # Secure Shell (SSH)
      SSH_KEY          = 'ssh-key'          # Secure Shell (SSH) Public Key
      TELNET           = 'telnet'           # TELNET
      MYSQL            = 'mysql'            # MySQL Server
      DB2              = 'db2'              # DB2
    end

    # Permission Elevation / Privilege Escalation Types.
    module ElevationType
      NONE   = 'NONE'
      SUDO   = 'SUDO'
      SUDOSU = 'SUDOSU'
      SU     = 'SU'
      PBRUN  = 'PBRUN'
      ENABLE = 'PRIVILEGEDEXEC' # Cisco Enable/ Privileged Exec
    end

    # Authentication type for SNMP version 3
    module AuthenticationType
      NOAUTH = 'noauth' # No authentication protocol
      SHA    = 'sha'    # SHA authentication protocol
      MD5    = 'md5'    # MD5 authentication protocol
    end

    # PrivacyType for snmp version 3
    module PrivacyType
      NOPRIV                     = 'nopriv'                     # No privacy protocol
      DES                        = 'des'                        # DES privacy protocol
      AES128                     = 'aes128'                     # AES128 privacy protocol
      AES192                     = 'aes192'                     # AES192 privacy protocol
      AES192WITH3DESKEYEXTENSION = 'aes192with3deskeyextension' # AES192 with 3 DES key extension privacy protocol
      AES256                     = 'aes256'                     # AES256 privacy protocol
      AES265WITH3DESKEYEXTENSION = 'aes265with3deskeyextension' # AES256 with 3 DES key extension privacy protocol
    end

  end
end
