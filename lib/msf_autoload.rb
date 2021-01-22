require 'zeitwerk'

###
# TODO:
# Apply zeitwerk to the rest of framework
# Namespacing wmap/events (when we're able to make potentially breaking changes)
# Correct namespacing to remove the custom inflector (or reduce it's complexity)
# Correct namespacing to cut down on inflector overrides
# Make the necessary changes to reduce/remove the ignored/collapsed files and folders
#
# I don't know why these are needed in `lib/msf/util/dot_net_deserialization/types.rb`
#   require 'msf/util/dot_net_deserialization/types/primitives'
#   require 'msf/util/dot_net_deserialization/types/general'
#   require 'msf/util/dot_net_deserialization/types/record_values'
###

class TempInflector < Zeitwerk::Inflector
  def camelize(basename, abspath)
    if basename == 'osx' && abspath.end_with?('lib/msf/core/payload/osx', 'lib/msf/core/payload/osx.rb')
      'Osx'
    elsif basename == 'exe' && abspath.end_with?('lib/msf/core/exe', 'lib/msf/core/exe.rb')
      'Exe'
    elsif basename == 'json' && abspath.end_with?('lib/msf/base/serializer/json.rb')
      'Json'
    elsif basename == 'powershell' && abspath.end_with?('lib/msf/base/sessions/powershell.rb')
      'PowerShell'
    elsif basename == 'ui' && abspath.end_with?('lib/msf/core/module/ui', 'lib/msf/core/module/ui.rb')
      'UI'
    else
      super
    end
  end
end

loader = Zeitwerk::Loader.new
loader.push_dir("#{__dir__}/msf/", namespace: Msf)
loader.push_dir("#{__dir__}/../app/validators/")

loader.ignore(
  "#{__dir__}/msf/core/constants.rb",
  "#{__dir__}/msf/core/cert_provider.rb",
  "#{__dir__}/msf/core/rpc/json/error.rb",
  "#{__dir__}/msf/core/rpc/json/v2_0/",
  "#{__dir__}/msf/core/modules/external/ruby/metasploit.rb",
  "#{__dir__}/msf/core/rpc/v10/constants.rb",
  "#{__dir__}/msf/core.rb",
  "#{__dir__}/msf/base.rb",
  )

loader.collapse(
  "#{__dir__}/msf/core",
  "#{__dir__}/msf/core/rpc/v10",
  "#{__dir__}/msf/core/payload/osx/x64",
  "#{__dir__}/msf/core/payload/windows/x64",
  "#{__dir__}/msf/core/payload/linux/x64",
  "#{__dir__}/msf/core/web_services/servlet",
  "#{__dir__}/msf/base",
  "#{__dir__}/msf/ui/console/command_dispatcher/db"
)

loader.inflector = TempInflector.new
loader.inflector.inflect(
  'opt_http_rhost_url' => 'OptHTTPRhostURL',
  'uuid' => 'UUID',
  'db_manager' => 'DBManager',
  'ci' => 'CI',
  'fusion_vm' => 'FusionVM',
  'gpp' => 'GPP',
  'ip360' => 'IP360',
  'aspl' => 'ASPL',
  'ip_list' => 'IPList',
  'mbsa' => 'MBSA',
  'xml' => 'XML',
  'nbe' => 'NBE',
  'open_vas' => 'OpenVAS',
  'ip_address' => 'IPAddress',
  'wmap' => 'WMAP',
  'reflective_dll_loader' => 'ReflectiveDLLLoader',
  'ssl' => 'SSL',
  'reverse_tcp_double_ssl' => 'ReverseTcpDoubleSSL',
  'rpc' => 'RPC',
  'db_import_error' => 'DBImportError',
  'db_export' => 'DBExport',
  'extapi' => 'ExtAPI',
  'nonalpha' => 'NonAlpha',
  'nonupper' => 'NonUpper',
  'natpmp' => 'NATPMP',
  'udp_scanner' => 'UDPScanner',
  'epmp' => 'EPMP',
  'cnpilot' => 'CNPILOT',
  'rservices' => 'RServices',
  'ntp' => 'NTP',
  'mqtt' => 'MQTT',
  'iax2' => 'IAX2',
  'pii' => 'PII',
  'mdns' => 'MDNS',
  'crand' => 'CRand',
  'llmnr' => 'LLMNR',
  'drdos' => 'DRDoS',
  'jsp' => 'JSP',
  'macho' => 'MachO',
  'nodejs' => 'NodeJS',
  'jsobfu' => 'JSObfu',
  'osx' => 'OSX',
  'webrtc' => 'WebRTC',
  'json' => 'JSON',
  'sip' => 'SIP',
  'ntlm' => 'NTLM',
  'mssql_commands' => 'MSSQL_COMMANDS',
  'mssql' => 'MSSQL',
  'pdf' => 'PDF',
  'fileformat' => 'FILEFORMAT',
  'http' => 'HTTP',
  'html' => 'HTML',
  'pdf_parse' => 'PDF_Parse',
  'vim_soap' => 'VIMSoap',
  'ndmp' => 'NDMP',
  'ndmp_socket' => 'NDMPSocket',
  'dcerpc' => 'DCERPC',
  'dcerpc_mgmt' => 'DCERPC_MGMT',
  'dcerpc_epm' => 'DCERPC_EPM',
  'dcerpc_lsa' => 'DCERPC_LSA',
  'wdbrpc_client' => 'WDBRPC_Client',
  'sunrpc' => 'SunRPC',
  'mysql' => 'MYSQL',
  'ldap' => 'LDAP',
  'sqli' => 'SQLi',
  'dhcp_server' => 'DHCPServer',
  'tns' => 'TNS',
  'oracle' => 'ORACLE',
  'dect_coa' => 'DECT_COA',
  'wdbrpc' => 'WDBRPC',
  'exe' => 'EXE',
  'php_exe' => 'PhpEXE',
  'mssql_sqli' => 'MSSQL_SQLI',
  'snmp_client' => 'SNMPClient',
  'afp' => 'AFP',
  'zeromq' => 'ZeroMQ',
  'tftp_server' => 'TFTPServer',
  'db2' => 'DB2',
  'rdp' => 'RDP',
  'riff' => 'RIFF',
  'dns' => 'DNS',
  'smtp_deliver' => 'SMTPDeliver',
  'send_uuid' => 'SendUUID',
  'exec_x64' => 'Exec_x64',
  'reflective_dll_injection' => 'ReflectiveDLLInjection',
  'reflective_pe_loader' => 'ReflectivePELoader',
  'pe_inject' => 'PEInject',
  'payload_db_conf' => 'PayloadDBConf',
  'reverse_tcp_x86' => 'ReverseTcp_x86',
  'ruby_dl' => 'RubyDL',
  'wmic' => 'WMIC',
  'net_api' => 'NetAPI',
  'rpc_base' => 'RPC_Base',
  'rpc_plugin' => 'RPC_Plugin',
  'rpc_db' => 'RPC_Db',
  'rpc_console' => 'RPC_Console',
  'rpc_session' => 'RPC_Session',
  'rpc_auth' => 'RPC_Auth',
  'rpc_job' => 'RPC_Job',
  'rpc_core' => 'RPC_Core',
  'rpc_module' => 'RPC_Module',
  'cli' => 'CLI',
  'sqlitei' => 'SQLitei',
  'mysqli' => 'MySQLi',
  'ssh' => 'SSH',
  'winrm' => 'WinRM',
  'smb' => 'SMB',
  'uris' => 'URIs',
  'jboss' => 'JBoss',
  'send_uuid_x64' => 'SendUUID_x64',
  'reverse_tcp_x64' => 'ReverseTcp_x64',
  'block_api_x64' => 'BlockApi_x64',
  'exitfunk_x64' => 'Exitfunk_x64',
  'reverse_http_x64' => 'ReverseHttp_x64',
  'rc4_x64' => 'Rc4_x64',
  'bind_tcp_x64' => 'BindTcp_x64',
  'reverse_win_http_x64' => 'ReverseWinHttp_x64',
  'reflective_dll_inject_x64' => 'ReflectiveDllInject_x64',
  'reverse_win_https_x64' => 'ReverseWinHttps_x64',
  'reflective_pe_loader_x64' => 'ReflectivePELoader_x64',
  'migrate_http_x64' => 'MigrateHttp_x64',
  'migrate_common_x64' => 'MigrateCommon_x64',
  'migrate_tcp_x64' => 'MigrateTcp_x64',
  'migrate_named_pipe_x64' => 'MigrateNamedPipe_x64',
  'reverse_named_pipe_x64' => 'ReverseNamedPipe_x64',
  'meterpreter_loader_x64' => 'MeterpreterLoader_x64',
  'rftransceiver' => 'RFTransceiver',
  'dtc' => 'DTC',
  'uds' => 'UDS',
  'v1_0' => 'V1_0',
  'php_include' => 'PHPInclude',
  'psexec_ms17_010' => 'Psexec_MS17_010',
  'bind_tcp_rc4_x64' => 'BindTcpRc4_x64',
  'reverse_tcp_rc4_x64' => 'ReverseTcpRc4_x64',
  'reverse_https_x64' => 'ReverseHttps_x64',
  'bind_named_pipe_x64' => 'BindNamedPipe_x64',
  'addr_loader' => 'AddrLoader_x64',
  'db_manager_proxy' => 'DBManagerProxy',
  'wmap_scan_ssl' => 'WmapScanSSL',
  'http_db_manager_service' => 'HttpDBManagerService',
  'vyos' => 'VYOS',
  'windows_constants' => 'Windows_Constants',
  'tty' => 'TTY',
  'meterpreter_java' => 'Meterpreter_Java_Java',
  'meterpreter_android' => 'Meterpreter_Java_Android',
  'meterpreter_zarch_linux' => 'Meterpreter_zarch_Linux',
  'meterpreter_python' => 'Meterpreter_Python_Python',
  'meterpreter_ppce500v2_linux' => 'Meterpreter_ppce500v2_Linux',
  'meterpreter_x86_osx' => 'Meterpreter_x86_OSX',
  'meterpreter_armbe_linux' => 'Meterpreter_armbe_Linux',
  'meterpreter_ppc64le_linux' => 'Meterpreter_ppc64le_Linux',
  'meterpreter_x64_linux' => 'Meterpreter_x64_Linux',
  'meterpreter_armle_linux' => 'Meterpreter_armle_Linux',
  'meterpreter_aarch64_linux' => 'Meterpreter_aarch64_Linux',
  'meterpreter_x86_win' => 'Meterpreter_x86_Win',
  'meterpreter_armle_apple_ios' => 'Meterpreter_armle_Apple_iOS',
  'meterpreter_mipsle_linux' => 'Meterpreter_mipsle_Linux',
  'meterpreter_x86_bsd' => 'Meterpreter_x86_BSD',
  'meterpreter_mips64_linux' => 'Meterpreter_mips64_Linux',
  'meterpreter_x86_linux' => 'Meterpreter_x86_Linux',
  'meterpreter_mipsbe_linux' => 'Meterpreter_mipsbe_Linux',
  'meterpreter_aarch64_apple_ios' => 'Meterpreter_aarch64_Apple_iOS',
  'meterpreter_x64_osx' => 'Meterpreter_x64_OSX',
  'meterpreter_ppc_linux' => 'Meterpreter_ppc_Linux',
  'meterpreter_x64_win' => 'Meterpreter_x64_Win',
  'meterpreter_php' => 'Meterpreter_Php_Php',
  'meterpreter_multi' => 'Meterpreter_Multi',
  'hwbridge' => 'HWBridge',
  'vncinject_options' => 'VncInjectOptions',
  'vncinject' => 'VncInject',
  )

loader.setup # ready!
