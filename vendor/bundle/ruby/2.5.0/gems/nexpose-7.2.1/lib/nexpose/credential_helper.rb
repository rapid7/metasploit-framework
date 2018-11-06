# frozen_string_literal: true

module Nexpose
  module CredentialHelper

    # sets the Concurrent Versioning System (CVS) service
    def set_cvs_service(username = nil, password = nil)
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::CVS
    end

    # sets the DB2 service
    def set_db2_service(database = nil, username = nil, password = nil)
      self.database  = database
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::DB2
    end

    # sets the File Transfer Protocol (FTP) service
    def set_ftp_service(username = nil, password = nil)
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::FTP
    end

    # sets the IBM AS/400 service.
    def set_as400_service(domain = nil, username = nil, password = nil)
      self.domain    = domain
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::AS400
    end

    # sets the Lotus Notes/Domino service.
    def set_notes_service(password = nil)
      self.notes_id_password = password
      self.service           = Credential::Service::NOTES
    end

    # sets the Microsoft SQL Server service.
    def set_tds_service(database = nil, domain = nil, username = nil, password = nil)
      self.database         = database
      self.domain           = domain
      self.use_windows_auth = domain.nil?
      self.user_name        = username
      self.password         = password
      self.service          = Credential::Service::TDS
    end

    # sets the Microsoft Windows/Samba (SMB/CIFS) service.
    def set_cifs_service(domain = nil, username = nil, password = nil)
      self.domain    = domain
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::CIFS
    end

    # sets the Microsoft Windows/Samba LM/NTLM Hash (SMB/CIFS) service.
    def set_cifshash_service(domain = nil, username = nil, password = nil)
      self.domain    = domain
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::CIFSHASH
    end

    # sets the MySQL Server service.
    def set_mysql_service(database = nil, username = nil, password = nil)
      self.database  = database
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::MYSQL
    end

    # sets the Oracle service.
    def set_oracle_service(sid = nil, username = nil, password = nil)
      self.database  = sid
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::ORACLE
    end

    # sets the Post Office Protocol (POP) service.
    def set_pop_service(username = nil, password = nil)
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::POP
    end

    # sets the PostgreSQL service.
    def set_postgresql_service(database = nil, username = nil, password = nil)
      self.database  = database
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::POSTGRESQL
    end

    # sets the Remote Execution service.
    def set_remote_execution_service(username = nil, password = nil)
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::REMOTE_EXECUTION
    end

    # sets the Secure Shell (SSH) service.
    def set_ssh_service(username = nil, password = nil, elevation_type = nil, elevation_user = nil, elevation_password = nil)
      self.user_name                     = username
      self.password                      = password
      self.permission_elevation_type     = elevation_type || Credential::ElevationType::NONE
      self.permission_elevation_user     = elevation_user
      self.permission_elevation_password = elevation_password
      self.service                       = Credential::Service::SSH
    end

    # sets the Secure Shell (SSH) Public Key service.
    def set_ssh_key_service(username, pemkey, password = nil, elevation_type = nil, elevation_user = nil, elevation_password = nil)
      self.user_name                     = username
      self.password                      = password
      self.pem_format_private_key        = pemkey
      self.permission_elevation_type     = elevation_type || Credential::ElevationType::NONE
      self.permission_elevation_user     = elevation_user
      self.permission_elevation_password = elevation_password
      self.service                       = Credential::Service::SSH_KEY
    end

    # sets the Simple Network Management Protocol v1/v2c service.
    def set_snmp_service(community_name = nil)
      self.community_name = community_name
      self.service        = Credential::Service::SNMP
    end

    # sets the Simple Network Management Protocol v3 service.
    def set_snmpv3_service(authentication_type = Credential::AuthenticationType::NOAUTH, username = nil, password = nil, privacy_type = Credential::PrivacyType::NOPRIV, privacy_password = nil)
      self.authentication_type = authentication_type
      self.user_name           = username
      self.password            = password
      self.privacy_type        = privacy_type
      self.privacy_password    = privacy_password
      self.service             = Credential::Service::SNMPV3
    end

    # sets the Sybase SQL Server service.
    def set_sybase_service(database = nil, domain = nil, username = nil, password = nil)
      self.database         = database
      self.domain           = domain
      self.use_windows_auth = domain.nil?
      self.user_name        = username
      self.password         = password
      self.service          = Credential::Service::SYBASE
    end

    # sets the Telnet service.
    def set_telnet_service(username = nil, password = nil)
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::TELNET
    end

    # sets the Web Site HTTP Authentication service.
    def set_http_service(domain = nil, username = nil, password = nil)
      self.domain    = domain
      self.user_name = username
      self.password  = password
      self.service   = Credential::Service::HTTP
    end

  end
end
