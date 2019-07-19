#
# Autoloads specific remote data services
#
module DataServiceAutoLoader
  autoload :RemoteHostDataService, 'metasploit/framework/data_service/remote/http/remote_host_data_service'
  autoload :RemoteEventDataService, 'metasploit/framework/data_service/remote/http/remote_event_data_service'
  autoload :RemoteNoteDataService, 'metasploit/framework/data_service/remote/http/remote_note_data_service'
  autoload :RemoteWorkspaceDataService, 'metasploit/framework/data_service/remote/http/remote_workspace_data_service'
  autoload :RemoteVulnDataService, 'metasploit/framework/data_service/remote/http/remote_vuln_data_service'
  autoload :RemoteWebDataService, 'metasploit/framework/data_service/remote/http/remote_web_data_service'
  autoload :RemoteServiceDataService, 'metasploit/framework/data_service/remote/http/remote_service_data_service'
  autoload :RemoteSessionDataService, 'metasploit/framework/data_service/remote/http/remote_session_data_service'
  autoload :RemoteExploitDataService, 'metasploit/framework/data_service/remote/http/remote_exploit_data_service'
  autoload :RemoteLootDataService, 'metasploit/framework/data_service/remote/http/remote_loot_data_service'
  autoload :RemoteSessionEventDataService, 'metasploit/framework/data_service/remote/http/remote_session_event_data_service'
  autoload :RemoteCredentialDataService, 'metasploit/framework/data_service/remote/http/remote_credential_data_service'
  autoload :RemoteLoginDataService, 'metasploit/framework/data_service/remote/http/remote_login_data_service'
  autoload :RemoteNmapDataService, 'metasploit/framework/data_service/remote/http/remote_nmap_data_service'
  autoload :RemoteDbExportDataService, 'metasploit/framework/data_service/remote/http/remote_db_export_data_service'
  autoload :RemoteVulnAttemptDataService, 'metasploit/framework/data_service/remote/http/remote_vuln_attempt_data_service'
  autoload :RemoteMsfDataService, 'metasploit/framework/data_service/remote/http/remote_msf_data_service'
  autoload :RemoteDbImportDataService, 'metasploit/framework/data_service/remote/http/remote_db_import_data_service.rb'
  autoload :RemotePayloadDataService, 'metasploit/framework/data_service/remote/http/remote_payload_data_service'
  autoload :RemoteAsyncCallbackDataService, 'metasploit/framework/data_service/remote/http/response_data_helper'

  include RemoteHostDataService
  include RemoteEventDataService
  include RemoteNoteDataService
  include RemoteWorkspaceDataService
  include RemoteVulnDataService
  include RemoteWebDataService
  include RemoteServiceDataService
  include RemoteSessionDataService
  include RemoteExploitDataService
  include RemoteLootDataService
  include RemoteSessionEventDataService
  include RemoteCredentialDataService
  include RemoteLoginDataService
  include RemoteNmapDataService
  include RemoteDbExportDataService
  include RemoteVulnAttemptDataService
  include RemoteMsfDataService
  include RemoteDbImportDataService
  include RemotePayloadDataService
  include RemoteAsyncCallbackDataService
end
