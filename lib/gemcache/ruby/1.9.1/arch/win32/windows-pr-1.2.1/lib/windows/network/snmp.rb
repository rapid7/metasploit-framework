require 'windows/api'

module Windows
  module Network
    module SNMP
      API.auto_namespace = 'Windows::Network::SNMP'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = false

      private

      SNMPAPI_FAILURE            = 0
      SNMPAPI_SUCCESS            = 1
      SNMPAPI_ALLOC_ERROR        = 2
      SNMPAPI_CONTEXT_INVALID    = 3
      SNMPAPI_CONTEXT_UNKNOWN    = 4
      SNMPAPI_ENTITY_INVALID     = 5
      SNMPAPI_ENTITY_UNKNOWN     = 6
      SNMPAPI_INDEX_INVALID      = 7
      SNMPAPI_NOOP               = 8
      SNMPAPI_OID_INVALID        = 9
      SNMPAPI_OPERATION_INVALID  = 10
      SNMPAPI_OUTPUT_TRUNCATED   = 11
      SNMPAPI_PDU_INVALID        = 12
      SNMPAPI_SESSION_INVALID    = 13
      SNMPAPI_SYNTAX_INVALID     = 14
      SNMPAPI_VBL_INVALID        = 15
      SNMPAPI_MODE_INVALID       = 16
      SNMPAPI_SIZE_INVALID       = 17
      SNMPAPI_NOT_INITIALIZED    = 18
      SNMPAPI_MESSAGE_INVALID    = 19
      SNMPAPI_HWND_INVALID       = 20
      SNMPAPI_OTHER_ERROR        = 99
      SNMPAPI_TL_NOT_INITIALIZED = 100
      SNMPAPI_TL_NOT_SUPPORTED   = 101
      SNMPAPI_TL_NOT_AVAILABLE   = 102
      SNMPAPI_TL_RESOURCE_ERROR  = 103
      SNMPAPI_TL_UNDELIVERABLE   = 104
      SNMPAPI_TL_SRC_INVALID     = 105
      SNMPAPI_TL_INVALID_PARAM   = 106
      SNMPAPI_TL_IN_USE          = 107
      SNMPAPI_TL_TIMEOUT         = 108
      SNMPAPI_TL_PDU_TOO_BIG     = 109
      SNMPAPI_TL_OTHER           = 199

      SNMPAPI_TRANSLATED       =  0
      SNMPAPI_UNTRANSLATED_V1  =  1
      SNMPAPI_UNTRANSLATED_V2  =  2
      SNMPAPI_NO_SUPPORT       =  0
      SNMPAPI_V1_SUPPORT       =  1
      SNMPAPI_V2_SUPPORT       =  2
      SNMPAPI_M2M_SUPPORT      =  3
      SNMPAPI_OFF              =  0
      SNMPAPI_ON               =  1

      API.new('SnmpCancelMsg', 'LI', 'I', 'wsnmp32')
      API.new('SnmpCleanup', 'V', 'I', 'wsnmp32')
      API.new('SnmpClose', 'L', 'I', 'wsnmp32')
      API.new('SnmpContextToStr', 'LP', 'I', 'wsnmp32')
      API.new('SnmpDecodeMsg', 'LPPPPP', 'I', 'wsnmp32')
      API.new('SnmpEncodeMsg', 'LLLLLP', 'I', 'wsnmp32')
      API.new('SnmpEntityToStr', 'LLP', 'I', 'wsnmp32')
      API.new('SnmpFreeContext', 'L', 'I', 'wsnmp32')
      API.new('SnmpFreeDescriptor', 'LP', 'I', 'wsnmp32')
      API.new('SnmpFreeEntity', 'L', 'I', 'wsnmp32')
      API.new('SnmpGetLastError', 'L', 'I', 'wsnmp32')
      API.new('SnmpListen', 'LL', 'I', 'wsnmp32')
      API.new('SnmpOidCompare', 'PPLP', 'I', 'wsnmp32')
      API.new('SnmpOidCopy', 'PP', 'I', 'wsnmp32')
      API.new('SnmpOidToStr', 'PLP', 'I', 'wsnmp32')
      API.new('SnmpOpen', 'LL', 'L', 'wsnmp32')
      API.new('SnmpRecvMsg', 'LPPPP', 'I', 'wsnmp32')
      API.new('SnmpRegister', 'LLLLPL', 'I', 'wsnmp32')
      API.new('SnmpSendMsg', 'LLLLL', 'I', 'wsnmp32')
      API.new('SnmpSetPort', 'LL', 'I', 'wsnmp32')
      API.new('SnmpStartup', 'PPPPP', 'I', 'wsnmp32')
      API.new('SnmpStrToContext', 'LP', 'I', 'wsnmp32')
      API.new('SnmpStrToEntity', 'LP', 'I', 'wsnmp32')
      API.new('SnmpStrToOid', 'PP', 'I', 'wsnmp32')

      # Windows 2003 Server or later and/or WinSNMP 2.0 or later
      begin
        API.new('SnmpCreateSession', 'LLKP', 'L', 'wsnmp32')
        API.new('SnmpCleanupEx', 'V', 'I', 'wsnmp32')
        API.new('SnmpStartupEx', 'PPPPP', 'L', 'wsnmp32')
      rescue Win32::API::LoadLibraryError
        # Do nothing. It's up to you to check for their existence.
      end
    end
  end
end
