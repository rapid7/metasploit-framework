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

class MsfAutoload
  include Singleton

  def initialize
    @loader = create_loader
    configure(@loader)
    finalize_loader(@loader)
  end

  class TempInflector < Zeitwerk::Inflector
    def camelize(basename, abspath)
      if basename == 'osx' && abspath.end_with?("#{__dir__}/msf/core/payload/osx", "#{__dir__}/msf/core/payload/osx.rb")
        'Osx'
      elsif basename == 'exe' && abspath.end_with?("#{__dir__}/msf/core/exe", "#{__dir__}/msf/core/exe.rb")
        'Exe'
      elsif basename == 'json' && abspath.end_with?("#{__dir__}/msf/base/serializer/json.rb")
        'Json'
      elsif basename == 'powershell' && abspath.end_with?("#{__dir__}/msf/base/sessions/powershell.rb")
        'PowerShell'
      elsif basename == 'ui' && abspath.end_with?("#{__dir__}/msf/core/module/ui", "#{__dir__}/msf/core/module/ui.rb", "#{__dir__}/rex/post/ui", "#{__dir__}/rex/post/ui.rb", "#{__dir__}/rex/post/meterpreter/extensions/stdapi/ui.rb")
        'UI'
      elsif basename == 'ssh' && abspath.end_with?("#{__dir__}/rex/proto/ssh")
        'Ssh'
      elsif basename == 'http' && abspath.end_with?("#{__dir__}/rex/proto/http")
        'Http'
      elsif basename == 'rftransceiver' && abspath.end_with?("#{__dir__}/rex/post/hwbridge/ui/console/command_dispatcher/rftransceiver.rb")
        'RFtransceiver'
      else
       super
    end
    end
  end

  private

  def ignore_list
    [
      "#{__dir__}/msf/core/constants.rb",
      "#{__dir__}/msf/core/cert_provider.rb",
      "#{__dir__}/msf/core/rpc/json/",
      "#{__dir__}/msf/core/modules/external/ruby/metasploit.rb",
      "#{__dir__}/msf/core/rpc/v10/constants.rb",
      "#{__dir__}/msf/core.rb",
      "#{__dir__}/msf/base.rb",
      "#{__dir__}/rex/post/",
      "#{__dir__}/rex/post.rb",
      "#{__dir__}/rex/proto/ssh/hrr_rb_ssh.rb",
      "#{__dir__}/rex/proto/ssh/connection.rb"
    ]
  end

  def collapse_list
    [
      "#{__dir__}/msf/core",
      "#{__dir__}/msf/core/rpc/v10",
      "#{__dir__}/msf/core/payload/osx/x64",
      "#{__dir__}/msf/core/payload/windows/x64",
      "#{__dir__}/msf/core/payload/linux/x64",
      "#{__dir__}/msf/core/web_services/servlet",
      "#{__dir__}/msf/base",
      "#{__dir__}/msf/ui/console/command_dispatcher/db",
      "#{__dir__}/rex/parser/fs"
    ]
  end

  def custom_inflections
    {
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
      'rpc_health' => 'RPC_Health',
      'rpc_module' => 'RPC_Module',
      'cli' => 'CLI',
      'sqlitei' => 'SQLitei',
      'mysqli' => 'MySQLi',
      'postgresqli' => 'PostgreSQLi',
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
      'json_hash_file' => 'JSONHashFile',
      'ndr' => 'NDR',
      'ci_document' => 'CIDocument',
      'fusionvm_document' => 'FusionVMDocument',
      'group_policy_preferences' => 'GPP',
      'ip360_aspl_xml' => 'IP360ASPLXMLStreamParser',
      'ip360_xml' => 'IP360XMLStreamParser',
      'nessus_xml' => 'NessusXMLStreamParser',
      'netsparker_xml' => 'NetSparkerXMLStreamParser',
      'nexpose_xml' => 'NexposeXMLStreamParser',
      'nmap_xml' => 'NmapXMLStreamParser',
      'openvas_document' => 'OpenVASDocument',
      'retina_xml' => 'RetinaXMLStreamParser',
      'graphml' => 'GraphML',
      'apple_backup_manifestdb' => 'AppleBackupManifestDB',
      'winscp' => 'WinSCP',
      'acpp' => 'ACPP',
      'tftp' => 'TFTP',
      'ipmi' => 'IPMI',
      'channel_auth_reply' => 'Channel_Auth_Reply',
      'open_session_reply' => 'Open_Session_Reply',
      'rakp2' => 'RAKP2',
      'pjl' => 'PJL',
      'dhcp' => 'DHCP',
      'addp' => 'ADDP',
      'rfb' => 'RFB',
      'io' => 'IO',
      'ntfs' => 'NTFS',
      'bitlocker' => 'BITLOCKER',
      'adb' => 'ADB',
      'drda' => 'DRDA',
      'tlv' => 'TLV',
      'svcctl' => 'SVCCTL',
      'wdscp' => 'WDSCP',
      'appapi' => 'AppApi',
      'uds_errors' => 'UDSErrors'
    }
  end

  def config_paths
    [
      { path: "#{__dir__}/msf/", namespace: Msf },
      { path: "#{__dir__}/rex/", namespace: Rex },
    ]
  end

  # Enables :prepend to inject  existing loader
  def create_loader
    Zeitwerk::Loader.new
  end

  # Enables :prepend to override the configuration items pass to the loader
  def configure(loader)
    config_paths.each do |entry|
      if entry[:namespace]
        loader.push_dir(entry[:path], namespace: entry[:namespace])
      else
        loader.push_dir(entry[:path])
      end
    end
    loader.ignore(ignore_list)
    loader.collapse(collapse_list)
    loader.inflector = TempInflector.new
    loader.inflector.inflect(custom_inflections)
  end

  # Enables :prepend to suppress the loader finalization
  def finalize_loader(loader)
    loader.setup # ready!
  end
end

# global autoload of common gems
autoload :Faker, 'faker'
autoload :BinData, 'bindata'
require 'rexml/document'
