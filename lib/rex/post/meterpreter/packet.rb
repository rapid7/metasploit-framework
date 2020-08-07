# -*- coding: binary -*-
require 'openssl'

module Rex
module Post
module Meterpreter

#
# Constants
#
PACKET_TYPE_REQUEST         = 0
PACKET_TYPE_RESPONSE        = 1
PACKET_TYPE_PLAIN_REQUEST   = 10
PACKET_TYPE_PLAIN_RESPONSE  = 11

#
# TLV Meta Types
#
TLV_META_TYPE_NONE          = 0
TLV_META_TYPE_STRING        = (1 << 16)
TLV_META_TYPE_UINT          = (1 << 17)
TLV_META_TYPE_RAW           = (1 << 18)
TLV_META_TYPE_BOOL          = (1 << 19)
TLV_META_TYPE_QWORD         = (1 << 20)
TLV_META_TYPE_COMPRESSED    = (1 << 29)
TLV_META_TYPE_GROUP         = (1 << 30)
TLV_META_TYPE_COMPLEX       = (1 << 31)

# Exclude compressed from the mask since other meta types (e.g. RAW) can also
# be compressed
TLV_META_MASK = (
  TLV_META_TYPE_STRING |
  TLV_META_TYPE_UINT |
  TLV_META_TYPE_RAW |
  TLV_META_TYPE_BOOL |
  TLV_META_TYPE_QWORD |
  TLV_META_TYPE_GROUP |
  TLV_META_TYPE_COMPLEX
)

#
# TLV base starting points
#
TLV_RESERVED                = 0
TLV_EXTENSIONS              = 20000
TLV_USER                    = 40000
TLV_TEMP                    = 60000

#
# TLV Specific Types
#
TLV_TYPE_ANY                 = TLV_META_TYPE_NONE   |   0
TLV_TYPE_COMMAND_ID          = TLV_META_TYPE_UINT   |   1
TLV_TYPE_REQUEST_ID          = TLV_META_TYPE_STRING |   2
TLV_TYPE_EXCEPTION           = TLV_META_TYPE_GROUP  |   3
TLV_TYPE_RESULT              = TLV_META_TYPE_UINT   |   4


TLV_TYPE_STRING              = TLV_META_TYPE_STRING |  10
TLV_TYPE_UINT                = TLV_META_TYPE_UINT   |  11
TLV_TYPE_BOOL                = TLV_META_TYPE_BOOL   |  12

TLV_TYPE_LENGTH              = TLV_META_TYPE_UINT   |  25
TLV_TYPE_DATA                = TLV_META_TYPE_RAW    |  26
TLV_TYPE_FLAGS               = TLV_META_TYPE_UINT   |  27

TLV_TYPE_CHANNEL_ID          = TLV_META_TYPE_UINT   |  50
TLV_TYPE_CHANNEL_TYPE        = TLV_META_TYPE_STRING |  51
TLV_TYPE_CHANNEL_DATA        = TLV_META_TYPE_RAW    |  52
TLV_TYPE_CHANNEL_DATA_GROUP  = TLV_META_TYPE_GROUP  |  53
TLV_TYPE_CHANNEL_CLASS       = TLV_META_TYPE_UINT   |  54
TLV_TYPE_CHANNEL_PARENTID    = TLV_META_TYPE_UINT   |  55

TLV_TYPE_SEEK_WHENCE         = TLV_META_TYPE_UINT   |  70
TLV_TYPE_SEEK_OFFSET         = TLV_META_TYPE_UINT   |  71
TLV_TYPE_SEEK_POS            = TLV_META_TYPE_UINT   |  72

TLV_TYPE_EXCEPTION_CODE      = TLV_META_TYPE_UINT   | 300
TLV_TYPE_EXCEPTION_STRING    = TLV_META_TYPE_STRING | 301

TLV_TYPE_LIBRARY_PATH        = TLV_META_TYPE_STRING | 400
TLV_TYPE_TARGET_PATH         = TLV_META_TYPE_STRING | 401
TLV_TYPE_MIGRATE_PID         = TLV_META_TYPE_UINT   | 402
TLV_TYPE_MIGRATE_PAYLOAD     = TLV_META_TYPE_RAW    | 404
TLV_TYPE_MIGRATE_ARCH        = TLV_META_TYPE_UINT   | 405
TLV_TYPE_MIGRATE_BASE_ADDR   = TLV_META_TYPE_UINT   | 407
TLV_TYPE_MIGRATE_ENTRY_POINT = TLV_META_TYPE_UINT   | 408
TLV_TYPE_MIGRATE_SOCKET_PATH = TLV_META_TYPE_STRING | 409
TLV_TYPE_MIGRATE_STUB        = TLV_META_TYPE_RAW    | 411
TLV_TYPE_LIB_LOADER_NAME     = TLV_META_TYPE_STRING | 412
TLV_TYPE_LIB_LOADER_ORDINAL  = TLV_META_TYPE_UINT   | 413

TLV_TYPE_TRANS_TYPE          = TLV_META_TYPE_UINT   | 430
TLV_TYPE_TRANS_URL           = TLV_META_TYPE_STRING | 431
TLV_TYPE_TRANS_UA            = TLV_META_TYPE_STRING | 432
TLV_TYPE_TRANS_COMM_TIMEOUT  = TLV_META_TYPE_UINT   | 433
TLV_TYPE_TRANS_SESSION_EXP   = TLV_META_TYPE_UINT   | 434
TLV_TYPE_TRANS_CERT_HASH     = TLV_META_TYPE_RAW    | 435
TLV_TYPE_TRANS_PROXY_HOST    = TLV_META_TYPE_STRING | 436
TLV_TYPE_TRANS_PROXY_USER    = TLV_META_TYPE_STRING | 437
TLV_TYPE_TRANS_PROXY_PASS    = TLV_META_TYPE_STRING | 438
TLV_TYPE_TRANS_RETRY_TOTAL   = TLV_META_TYPE_UINT   | 439
TLV_TYPE_TRANS_RETRY_WAIT    = TLV_META_TYPE_UINT   | 440
TLV_TYPE_TRANS_HEADERS       = TLV_META_TYPE_STRING | 441
TLV_TYPE_TRANS_GROUP         = TLV_META_TYPE_GROUP  | 442

TLV_TYPE_MACHINE_ID          = TLV_META_TYPE_STRING | 460
TLV_TYPE_UUID                = TLV_META_TYPE_RAW    | 461
TLV_TYPE_SESSION_GUID        = TLV_META_TYPE_RAW    | 462

TLV_TYPE_RSA_PUB_KEY         = TLV_META_TYPE_RAW    | 550
TLV_TYPE_SYM_KEY_TYPE        = TLV_META_TYPE_UINT   | 551
TLV_TYPE_SYM_KEY             = TLV_META_TYPE_RAW    | 552
TLV_TYPE_ENC_SYM_KEY         = TLV_META_TYPE_RAW    | 553

#
# Pivots
#
TLV_TYPE_PIVOT_ID              = TLV_META_TYPE_RAW    |  650
TLV_TYPE_PIVOT_STAGE_DATA      = TLV_META_TYPE_RAW    |  651
TLV_TYPE_PIVOT_NAMED_PIPE_NAME = TLV_META_TYPE_STRING |  653


#
# Core flags
#
LOAD_LIBRARY_FLAG_ON_DISK   = (1 << 0)
LOAD_LIBRARY_FLAG_EXTENSION = (1 << 1)
LOAD_LIBRARY_FLAG_LOCAL     = (1 << 2)

#
# Sane defaults
#
GUID_SIZE = 16
NULL_GUID = "\x00" * GUID_SIZE

#
# Mapping of command strings to identifiers
#
#
COMMAND_ID_START_CORE       = 0
COMMAND_ID_START_STDAPI     = 1000
COMMAND_ID_START_PRIV       = 2000
COMMAND_ID_START_EXTAPI     = 3000
COMMAND_ID_START_SNIFFER    = 4000
COMMAND_ID_START_ANDROID    = 5000
COMMAND_ID_START_NETWORKPUG = 6000
COMMAND_ID_START_WINPMEM    = 7000
COMMAND_ID_START_KIWI       = 8000
COMMAND_ID_START_APPAPI     = 9000
COMMAND_ID_START_UNHOOK     = 10000
COMMAND_ID_START_ESPIA      = 11000
COMMAND_ID_START_INCOGNITO  = 12000
COMMAND_ID_START_PYTHON     = 13000
COMMAND_ID_START_POWERSHELL = 14000
COMMAND_ID_START_LANATTACKS = 15000
COMMAND_ID_START_PEINJECTOR = 16000
COMMAND_ID_START_MIMIKATZ   = 17000

COMMAND_ID_MAP_CORE = {
  'core_channel_close'            => COMMAND_ID_START_CORE + 1,
  'core_channel_eof'              => COMMAND_ID_START_CORE + 2,
  'core_channel_interact'         => COMMAND_ID_START_CORE + 3,
  'core_channel_open'             => COMMAND_ID_START_CORE + 4,
  'core_channel_read'             => COMMAND_ID_START_CORE + 5,
  'core_channel_seek'             => COMMAND_ID_START_CORE + 6,
  'core_channel_tell'             => COMMAND_ID_START_CORE + 7,
  'core_channel_write'            => COMMAND_ID_START_CORE + 8,
  'core_console_write'            => COMMAND_ID_START_CORE + 9,
  'core_enumextcmd'               => COMMAND_ID_START_CORE + 10,
  'core_get_session_guid'         => COMMAND_ID_START_CORE + 11,
  'core_loadlib'                  => COMMAND_ID_START_CORE + 12,
  'core_machine_id'               => COMMAND_ID_START_CORE + 13,
  'core_migrate'                  => COMMAND_ID_START_CORE + 14,
  'core_native_arch'              => COMMAND_ID_START_CORE + 15,
  'core_negotiate_tlv_encryption' => COMMAND_ID_START_CORE + 16,
  'core_patch_url'                => COMMAND_ID_START_CORE + 17,
  'core_pivot_add'                => COMMAND_ID_START_CORE + 18,
  'core_pivot_remove'             => COMMAND_ID_START_CORE + 19,
  'core_pivot_session_died'       => COMMAND_ID_START_CORE + 20,
  'core_set_session_guid'         => COMMAND_ID_START_CORE + 21,
  'core_set_uuid'                 => COMMAND_ID_START_CORE + 22,
  'core_shutdown'                 => COMMAND_ID_START_CORE + 23,
  'core_transport_add'            => COMMAND_ID_START_CORE + 24,
  'core_transport_change'         => COMMAND_ID_START_CORE + 25,
  'core_transport_getcerthash'    => COMMAND_ID_START_CORE + 26,
  'core_transport_list'           => COMMAND_ID_START_CORE + 27,
  'core_transport_next'           => COMMAND_ID_START_CORE + 28,
  'core_transport_prev'           => COMMAND_ID_START_CORE + 29,
  'core_transport_remove'         => COMMAND_ID_START_CORE + 30,
  'core_transport_setcerthash'    => COMMAND_ID_START_CORE + 31,
  'core_transport_set_timeouts'   => COMMAND_ID_START_CORE + 32,
  'core_transport_sleep'          => COMMAND_ID_START_CORE + 33,
}

COMMAND_ID_MAP_STDAPI = {
  'stdapi_fs_chdir'                           => COMMAND_ID_START_STDAPI + 1,
  'stdapi_fs_chmod'                           => COMMAND_ID_START_STDAPI + 2,
  'stdapi_fs_delete_dir'                      => COMMAND_ID_START_STDAPI + 3,
  'stdapi_fs_delete_file'                     => COMMAND_ID_START_STDAPI + 4,
  'stdapi_fs_file_copy'                       => COMMAND_ID_START_STDAPI + 5,
  'stdapi_fs_file_expand_path'                => COMMAND_ID_START_STDAPI + 6,
  'stdapi_fs_file_move'                       => COMMAND_ID_START_STDAPI + 7,
  'stdapi_fs_getwd'                           => COMMAND_ID_START_STDAPI + 8,
  'stdapi_fs_ls'                              => COMMAND_ID_START_STDAPI + 9,
  'stdapi_fs_md5'                             => COMMAND_ID_START_STDAPI + 10,
  'stdapi_fs_mkdir'                           => COMMAND_ID_START_STDAPI + 11,
  'stdapi_fs_mount_show'                      => COMMAND_ID_START_STDAPI + 12,
  'stdapi_fs_search'                          => COMMAND_ID_START_STDAPI + 13,
  'stdapi_fs_separator'                       => COMMAND_ID_START_STDAPI + 14,
  'stdapi_fs_sha1'                            => COMMAND_ID_START_STDAPI + 15,
  'stdapi_fs_stat'                            => COMMAND_ID_START_STDAPI + 16,
  'stdapi_net_config_add_route'               => COMMAND_ID_START_STDAPI + 17,
  'stdapi_net_config_get_arp_table'           => COMMAND_ID_START_STDAPI + 18,
  'stdapi_net_config_get_interfaces'          => COMMAND_ID_START_STDAPI + 19,
  'stdapi_net_config_get_netstat'             => COMMAND_ID_START_STDAPI + 20,
  'stdapi_net_config_get_proxy'               => COMMAND_ID_START_STDAPI + 21,
  'stdapi_net_config_get_routes'              => COMMAND_ID_START_STDAPI + 22,
  'stdapi_net_config_remove_route'            => COMMAND_ID_START_STDAPI + 23,
  'stdapi_net_resolve_host'                   => COMMAND_ID_START_STDAPI + 24,
  'stdapi_net_resolve_hosts'                  => COMMAND_ID_START_STDAPI + 25,
  'stdapi_net_socket_tcp_shutdown'            => COMMAND_ID_START_STDAPI + 26,
  'stdapi_net_tcp_channel_open'               => COMMAND_ID_START_STDAPI + 27,
  'stdapi_railgun_api'                        => COMMAND_ID_START_STDAPI + 28,
  'stdapi_railgun_api_multi'                  => COMMAND_ID_START_STDAPI + 29,
  'stdapi_railgun_memread'                    => COMMAND_ID_START_STDAPI + 30,
  'stdapi_railgun_memwrite'                   => COMMAND_ID_START_STDAPI + 31,
  'stdapi_registry_check_key_exists'          => COMMAND_ID_START_STDAPI + 32,
  'stdapi_registry_close_key'                 => COMMAND_ID_START_STDAPI + 33,
  'stdapi_registry_create_key'                => COMMAND_ID_START_STDAPI + 34,
  'stdapi_registry_delete_key'                => COMMAND_ID_START_STDAPI + 35,
  'stdapi_registry_delete_value'              => COMMAND_ID_START_STDAPI + 36,
  'stdapi_registry_enum_key'                  => COMMAND_ID_START_STDAPI + 37,
  'stdapi_registry_enum_key_direct'           => COMMAND_ID_START_STDAPI + 38,
  'stdapi_registry_enum_value'                => COMMAND_ID_START_STDAPI + 39,
  'stdapi_registry_enum_value_direct'         => COMMAND_ID_START_STDAPI + 40,
  'stdapi_registry_load_key'                  => COMMAND_ID_START_STDAPI + 41,
  'stdapi_registry_open_key'                  => COMMAND_ID_START_STDAPI + 42,
  'stdapi_registry_open_remote_key'           => COMMAND_ID_START_STDAPI + 43,
  'stdapi_registry_query_class'               => COMMAND_ID_START_STDAPI + 44,
  'stdapi_registry_query_value'               => COMMAND_ID_START_STDAPI + 45,
  'stdapi_registry_query_value_direct'        => COMMAND_ID_START_STDAPI + 46,
  'stdapi_registry_set_value'                 => COMMAND_ID_START_STDAPI + 47,
  'stdapi_registry_set_value_direct'          => COMMAND_ID_START_STDAPI + 48,
  'stdapi_registry_unload_key'                => COMMAND_ID_START_STDAPI + 49,
  'stdapi_sys_config_driver_list'             => COMMAND_ID_START_STDAPI + 50,
  'stdapi_sys_config_drop_token'              => COMMAND_ID_START_STDAPI + 51,
  'stdapi_sys_config_getenv'                  => COMMAND_ID_START_STDAPI + 52,
  'stdapi_sys_config_getprivs'                => COMMAND_ID_START_STDAPI + 53,
  'stdapi_sys_config_getsid'                  => COMMAND_ID_START_STDAPI + 54,
  'stdapi_sys_config_getuid'                  => COMMAND_ID_START_STDAPI + 55,
  'stdapi_sys_config_localtime'               => COMMAND_ID_START_STDAPI + 56,
  'stdapi_sys_config_rev2self'                => COMMAND_ID_START_STDAPI + 57,
  'stdapi_sys_config_steal_token'             => COMMAND_ID_START_STDAPI + 58,
  'stdapi_sys_config_sysinfo'                 => COMMAND_ID_START_STDAPI + 59,
  'stdapi_sys_eventlog_clear'                 => COMMAND_ID_START_STDAPI + 60,
  'stdapi_sys_eventlog_close'                 => COMMAND_ID_START_STDAPI + 61,
  'stdapi_sys_eventlog_numrecords'            => COMMAND_ID_START_STDAPI + 62,
  'stdapi_sys_eventlog_oldest'                => COMMAND_ID_START_STDAPI + 63,
  'stdapi_sys_eventlog_open'                  => COMMAND_ID_START_STDAPI + 64,
  'stdapi_sys_eventlog_read'                  => COMMAND_ID_START_STDAPI + 65,
  'stdapi_sys_power_exitwindows'              => COMMAND_ID_START_STDAPI + 66,
  'stdapi_sys_process_attach'                 => COMMAND_ID_START_STDAPI + 67,
  'stdapi_sys_process_close'                  => COMMAND_ID_START_STDAPI + 68,
  'stdapi_sys_process_execute'                => COMMAND_ID_START_STDAPI + 69,
  'stdapi_sys_process_get_info'               => COMMAND_ID_START_STDAPI + 70,
  'stdapi_sys_process_get_processes'          => COMMAND_ID_START_STDAPI + 71,
  'stdapi_sys_process_getpid'                 => COMMAND_ID_START_STDAPI + 72,
  'stdapi_sys_process_image_get_images'       => COMMAND_ID_START_STDAPI + 73,
  'stdapi_sys_process_image_get_proc_address' => COMMAND_ID_START_STDAPI + 74,
  'stdapi_sys_process_image_load'             => COMMAND_ID_START_STDAPI + 75,
  'stdapi_sys_process_image_unload'           => COMMAND_ID_START_STDAPI + 76,
  'stdapi_sys_process_kill'                   => COMMAND_ID_START_STDAPI + 77,
  'stdapi_sys_process_memory_allocate'        => COMMAND_ID_START_STDAPI + 78,
  'stdapi_sys_process_memory_free'            => COMMAND_ID_START_STDAPI + 79,
  'stdapi_sys_process_memory_lock'            => COMMAND_ID_START_STDAPI + 80,
  'stdapi_sys_process_memory_protect'         => COMMAND_ID_START_STDAPI + 81,
  'stdapi_sys_process_memory_query'           => COMMAND_ID_START_STDAPI + 82,
  'stdapi_sys_process_memory_read'            => COMMAND_ID_START_STDAPI + 83,
  'stdapi_sys_process_memory_unlock'          => COMMAND_ID_START_STDAPI + 84,
  'stdapi_sys_process_memory_write'           => COMMAND_ID_START_STDAPI + 85,
  'stdapi_sys_process_thread_close'           => COMMAND_ID_START_STDAPI + 86,
  'stdapi_sys_process_thread_create'          => COMMAND_ID_START_STDAPI + 87,
  'stdapi_sys_process_thread_get_threads'     => COMMAND_ID_START_STDAPI + 88,
  'stdapi_sys_process_thread_open'            => COMMAND_ID_START_STDAPI + 89,
  'stdapi_sys_process_thread_query_regs'      => COMMAND_ID_START_STDAPI + 90,
  'stdapi_sys_process_thread_resume'          => COMMAND_ID_START_STDAPI + 91,
  'stdapi_sys_process_thread_set_regs'        => COMMAND_ID_START_STDAPI + 92,
  'stdapi_sys_process_thread_suspend'         => COMMAND_ID_START_STDAPI + 93,
  'stdapi_sys_process_thread_terminate'       => COMMAND_ID_START_STDAPI + 94,
  'stdapi_sys_process_wait'                   => COMMAND_ID_START_STDAPI + 95,
  'stdapi_ui_desktop_enum'                    => COMMAND_ID_START_STDAPI + 96,
  'stdapi_ui_desktop_get'                     => COMMAND_ID_START_STDAPI + 97,
  'stdapi_ui_desktop_screenshot'              => COMMAND_ID_START_STDAPI + 98,
  'stdapi_ui_desktop_set'                     => COMMAND_ID_START_STDAPI + 99,
  'stdapi_ui_enable_keyboard'                 => COMMAND_ID_START_STDAPI + 100,
  'stdapi_ui_enable_mouse'                    => COMMAND_ID_START_STDAPI + 101,
  'stdapi_ui_get_idle_time'                   => COMMAND_ID_START_STDAPI + 102,
  'stdapi_ui_get_keys_utf8'                   => COMMAND_ID_START_STDAPI + 103,
  'stdapi_ui_send_keyevent'                   => COMMAND_ID_START_STDAPI + 104,
  'stdapi_ui_send_keys'                       => COMMAND_ID_START_STDAPI + 105,
  'stdapi_ui_send_mouse'                      => COMMAND_ID_START_STDAPI + 106,
  'stdapi_ui_start_keyscan'                   => COMMAND_ID_START_STDAPI + 107,
  'stdapi_ui_stop_keyscan'                    => COMMAND_ID_START_STDAPI + 108,
  'stdapi_ui_unlock_desktop'                  => COMMAND_ID_START_STDAPI + 109,
  'stdapi_webcam_audio_record'                => COMMAND_ID_START_STDAPI + 110,
  'stdapi_webcam_get_frame'                   => COMMAND_ID_START_STDAPI + 111,
  'stdapi_webcam_list'                        => COMMAND_ID_START_STDAPI + 112,
  'stdapi_webcam_start'                       => COMMAND_ID_START_STDAPI + 113,
  'stdapi_webcam_stop'                        => COMMAND_ID_START_STDAPI + 114,
}

COMMAND_ID_MAP_ANDROID = {
  'android_activity_start'   => COMMAND_ID_START_ANDROID + 1,
  'android_check_root'       => COMMAND_ID_START_ANDROID + 2,
  'android_device_shutdown'  => COMMAND_ID_START_ANDROID + 3,
  'android_dump_calllog'     => COMMAND_ID_START_ANDROID + 4,
  'android_dump_contacts'    => COMMAND_ID_START_ANDROID + 5,
  'android_dump_sms'         => COMMAND_ID_START_ANDROID + 6,
  'android_geolocate'        => COMMAND_ID_START_ANDROID + 7,
  'android_hide_app_icon'    => COMMAND_ID_START_ANDROID + 8,
  'android_interval_collect' => COMMAND_ID_START_ANDROID + 9,
  'android_send_sms'         => COMMAND_ID_START_ANDROID + 10,
  'android_set_audio_mode'   => COMMAND_ID_START_ANDROID + 11,
  'android_set_wallpaper'    => COMMAND_ID_START_ANDROID + 12,
  'android_sqlite_query'     => COMMAND_ID_START_ANDROID + 13,
  'android_wakelock'         => COMMAND_ID_START_ANDROID + 14,
  'android_wlan_geolocate'   => COMMAND_ID_START_ANDROID + 15,
}

COMMAND_ID_MAP_APPAPI = {
  'appapi_app_install'   => COMMAND_ID_START_APPAPI + 1,
  'appapi_app_list'      => COMMAND_ID_START_APPAPI + 2,
  'appapi_app_run'       => COMMAND_ID_START_APPAPI + 3,
  'appapi_app_uninstall' => COMMAND_ID_START_APPAPI + 4,
}

COMMAND_ID_MAP_WINPMEM = {
  'winpmem_dump_ram' => COMMAND_ID_START_WINPMEM + 1,
}

COMMAND_ID_MAP_ESPIA = {
  'espia_image_get_dev_screen' => COMMAND_ID_START_ESPIA + 1,
}

COMMAND_ID_MAP_EXTAPI = {
  'extapi_adsi_domain_query'        => COMMAND_ID_START_EXTAPI + 1,
  'extapi_clipboard_get_data'       => COMMAND_ID_START_EXTAPI + 2,
  'extapi_clipboard_monitor_dump'   => COMMAND_ID_START_EXTAPI + 3,
  'extapi_clipboard_monitor_pause'  => COMMAND_ID_START_EXTAPI + 4,
  'extapi_clipboard_monitor_purge'  => COMMAND_ID_START_EXTAPI + 5,
  'extapi_clipboard_monitor_resume' => COMMAND_ID_START_EXTAPI + 6,
  'extapi_clipboard_monitor_start'  => COMMAND_ID_START_EXTAPI + 7,
  'extapi_clipboard_monitor_stop'   => COMMAND_ID_START_EXTAPI + 8,
  'extapi_clipboard_set_data'       => COMMAND_ID_START_EXTAPI + 9,
  'extapi_ntds_parse'               => COMMAND_ID_START_EXTAPI + 10,
  'extapi_pageant_send_query'       => COMMAND_ID_START_EXTAPI + 11,
  'extapi_service_control'          => COMMAND_ID_START_EXTAPI + 12,
  'extapi_service_enum'             => COMMAND_ID_START_EXTAPI + 13,
  'extapi_service_query'            => COMMAND_ID_START_EXTAPI + 14,
  'extapi_window_enum'              => COMMAND_ID_START_EXTAPI + 15,
  'extapi_wmi_query'                => COMMAND_ID_START_EXTAPI + 16,
}

COMMAND_ID_MAP_INCOGNITO = {
  'incognito_add_group_user'      => COMMAND_ID_START_INCOGNITO + 1,
  'incognito_add_localgroup_user' => COMMAND_ID_START_INCOGNITO + 2,
  'incognito_add_user'            => COMMAND_ID_START_INCOGNITO + 3,
  'incognito_impersonate_token'   => COMMAND_ID_START_INCOGNITO + 4,
  'incognito_list_tokens'         => COMMAND_ID_START_INCOGNITO + 5,
  'incognito_snarf_hashes'        => COMMAND_ID_START_INCOGNITO + 6,
}

COMMAND_ID_MAP_KIWI = {
  'kiwi_exec_cmd' => COMMAND_ID_START_KIWI + 1,
}

COMMAND_ID_MAP_LANATTACKS = {
  'lanattacks_add_tftp_file'   => COMMAND_ID_START_LANATTACKS + 1,
  'lanattacks_dhcp_log'        => COMMAND_ID_START_LANATTACKS + 2,
  'lanattacks_reset_dhcp'      => COMMAND_ID_START_LANATTACKS + 3,
  'lanattacks_reset_tftp'      => COMMAND_ID_START_LANATTACKS + 4,
  'lanattacks_set_dhcp_option' => COMMAND_ID_START_LANATTACKS + 5,
  'lanattacks_start_dhcp'      => COMMAND_ID_START_LANATTACKS + 6,
  'lanattacks_start_tftp'      => COMMAND_ID_START_LANATTACKS + 7,
  'lanattacks_stop_dhcp'       => COMMAND_ID_START_LANATTACKS + 8,
  'lanattacks_stop_tftp'       => COMMAND_ID_START_LANATTACKS + 9,
}

COMMAND_ID_MAP_MIMIKATZ = {
  'mimikatz_custom_command' => COMMAND_ID_START_MIMIKATZ + 1,
}

COMMAND_ID_MAP_NETWORKPUG = {
  'networkpug_start' => COMMAND_ID_START_NETWORKPUG + 1,
  'networkpug_stop'  => COMMAND_ID_START_NETWORKPUG + 2,
}

COMMAND_ID_MAP_PEINJECTOR = {
  'peinjector_inject_shellcode' => COMMAND_ID_START_PEINJECTOR + 1,
}

COMMAND_ID_MAP_POWERSHELL = {
  'powershell_assembly_load'  => COMMAND_ID_START_POWERSHELL + 1,
  'powershell_execute'        => COMMAND_ID_START_POWERSHELL + 2,
  'powershell_session_remove' => COMMAND_ID_START_POWERSHELL + 3,
  'powershell_shell'          => COMMAND_ID_START_POWERSHELL + 4,
}

COMMAND_ID_MAP_PRIV = {
  'priv_elevate_getsystem'          => COMMAND_ID_START_PRIV + 1,
  'priv_fs_blank_directory_mace'    => COMMAND_ID_START_PRIV + 2,
  'priv_fs_blank_file_mace'         => COMMAND_ID_START_PRIV + 3,
  'priv_fs_get_file_mace'           => COMMAND_ID_START_PRIV + 4,
  'priv_fs_set_file_mace'           => COMMAND_ID_START_PRIV + 5,
  'priv_fs_set_file_mace_from_file' => COMMAND_ID_START_PRIV + 6,
  'priv_passwd_get_sam_hashes'      => COMMAND_ID_START_PRIV + 7,
}

COMMAND_ID_MAP_PYTHON = {
  'python_execute' => COMMAND_ID_START_PYTHON + 1,
  'python_reset'   => COMMAND_ID_START_PYTHON + 2,
}

COMMAND_ID_MAP_SNIFFER = {
  'sniffer_capture_dump'      => COMMAND_ID_START_SNIFFER + 1,
  'sniffer_capture_dump_read' => COMMAND_ID_START_SNIFFER + 2,
  'sniffer_capture_release'   => COMMAND_ID_START_SNIFFER + 3,
  'sniffer_capture_start'     => COMMAND_ID_START_SNIFFER + 4,
  'sniffer_capture_stats'     => COMMAND_ID_START_SNIFFER + 5,
  'sniffer_capture_stop'      => COMMAND_ID_START_SNIFFER + 6,
  'sniffer_interfaces'        => COMMAND_ID_START_SNIFFER + 7,
  }

COMMAND_ID_MAP_UNHOOK = {
  'unhook_pe' => COMMAND_ID_START_UNHOOK + 1,
}

COMMAND_ID_MAP = [
  COMMAND_ID_MAP_CORE,
  COMMAND_ID_MAP_STDAPI,
  COMMAND_ID_MAP_PRIV,
  COMMAND_ID_MAP_EXTAPI,
  COMMAND_ID_MAP_SNIFFER,
  COMMAND_ID_MAP_ANDROID,
  COMMAND_ID_MAP_NETWORKPUG,
  COMMAND_ID_MAP_WINPMEM,
  COMMAND_ID_MAP_KIWI,
  COMMAND_ID_MAP_APPAPI,
  COMMAND_ID_MAP_UNHOOK,
  COMMAND_ID_MAP_ESPIA,
  COMMAND_ID_MAP_INCOGNITO,
  COMMAND_ID_MAP_PYTHON,
  COMMAND_ID_MAP_POWERSHELL,
  COMMAND_ID_MAP_LANATTACKS,
  COMMAND_ID_MAP_PEINJECTOR,
  COMMAND_ID_MAP_MIMIKATZ,
].inject({}) {|m1, m2| m1.merge(m2)}

def self.generate_command_id_map_c
  id_map = [
    COMMAND_ID_MAP_CORE,
    COMMAND_ID_MAP_STDAPI,
    COMMAND_ID_MAP_PRIV,
    COMMAND_ID_MAP_EXTAPI,
    COMMAND_ID_MAP_SNIFFER,
    COMMAND_ID_MAP_WINPMEM,
    COMMAND_ID_MAP_KIWI,
    COMMAND_ID_MAP_UNHOOK,
    COMMAND_ID_MAP_ESPIA,
    COMMAND_ID_MAP_INCOGNITO,
    COMMAND_ID_MAP_PYTHON,
    COMMAND_ID_MAP_POWERSHELL,
    COMMAND_ID_MAP_LANATTACKS,
    COMMAND_ID_MAP_PEINJECTOR,
    COMMAND_ID_MAP_MIMIKATZ,
  ].inject({}) {|m1, m2| m1.merge(m2)}

  command_ids = id_map.map {|k, v| "#define COMMAND_ID_#{k.upcase} #{v}"}
  %Q^
/*!
 * @file common_command_ids.h
 * @brief Declarations of command ID values
 * @description This file was generated #{Time.now.utc}. Do not modify directly.
 */
#ifndef _METERPRETER_SOURCE_COMMON_COMMAND_IDS_H
#define _METERPRETER_SOURCE_COMMON_COMMAND_IDS_H

#{command_ids.join("\n")}

#endif
  ^
end

def self.generate_command_id_map_java
  id_map = [
    COMMAND_ID_MAP_CORE,
    COMMAND_ID_MAP_STDAPI,
  ].inject({}) {|m1, m2| m1.merge(m2)}
  command_ids = id_map.map {|k, v| "    public static final int #{k.upcase} = #{v};"}
  %Q^
package com.metasploit.meterpreter.command;

/**
 * All supported Command Identifiers
 *
 * @author Genereated by a tool @ #{Time.now.utc}
 */
public interface CommandId {
#{command_ids.join("\n")}
}
  ^
end

def self.generate_command_id_map_php_lib(lib, id_map)
  command_ids = id_map.map {|k, v| "define('COMMAND_ID_#{k.upcase}', #{v});"}
  %Q^
# ---------------------------------------------------------------
# --- THIS CONTENT WAS GENERATED BY A TOOL @ #{Time.now.utc}
# IDs for #{lib}
#{command_ids.join("\n")}
# ---------------------------------------------------------------
  ^
end

def self.generate_command_id_map_php
  %Q^
#{self.generate_command_id_map_php_lib('metsrv', COMMAND_ID_MAP_CORE)}

#{self.generate_command_id_map_php_lib('stdapi', COMMAND_ID_MAP_STDAPI)}
  ^
end

def self.generate_command_id_map_python
  id_map = [
    COMMAND_ID_MAP_CORE,
    COMMAND_ID_MAP_STDAPI,
  ].inject({}) {|m1, m2| m1.merge(m2)}
  command_ids = id_map.map {|k, v| "    (#{v}, '#{k.downcase}'),"}
  %Q^
# ---------------------------------------------------------------
# --- THIS CONTENT WAS GENERATED BY A TOOL @ #{Time.now.utc}
COMMAND_IDS = (
#{command_ids.join("\n")}
)
# ---------------------------------------------------------------
  ^
end

def self.generate_command_id_map_python_extension
  id_map = [
    COMMAND_ID_MAP_CORE,
    COMMAND_ID_MAP_STDAPI,
    COMMAND_ID_MAP_PRIV,
    COMMAND_ID_MAP_EXTAPI,
    COMMAND_ID_MAP_SNIFFER,
    COMMAND_ID_MAP_WINPMEM,
    COMMAND_ID_MAP_KIWI,
    COMMAND_ID_MAP_UNHOOK,
    COMMAND_ID_MAP_ESPIA,
    COMMAND_ID_MAP_INCOGNITO,
    COMMAND_ID_MAP_PYTHON,
    COMMAND_ID_MAP_POWERSHELL,
    COMMAND_ID_MAP_LANATTACKS,
    COMMAND_ID_MAP_PEINJECTOR,
    COMMAND_ID_MAP_MIMIKATZ,
  ].inject({}) {|m1, m2| m1.merge(m2)}
  command_ids = id_map.map {|k, v| "COMMAND_ID_#{k.upcase} = #{v}"}
  %Q^
# ---------------------------------------------------------------
# --- THIS CONTENT WAS GENERATED BY A TOOL @ #{Time.now.utc}

#{command_ids.join("\n")}

# ---------------------------------------------------------------
  ^
end

def self.generate_command_id_map_csharp
  id_map = [
    COMMAND_ID_MAP_CORE,
    COMMAND_ID_MAP_STDAPI,
    COMMAND_ID_MAP_PRIV,
    COMMAND_ID_MAP_EXTAPI,
    COMMAND_ID_MAP_SNIFFER,
    COMMAND_ID_MAP_WINPMEM,
    COMMAND_ID_MAP_KIWI,
    COMMAND_ID_MAP_UNHOOK,
    COMMAND_ID_MAP_ESPIA,
    COMMAND_ID_MAP_INCOGNITO,
    COMMAND_ID_MAP_PYTHON,
    COMMAND_ID_MAP_POWERSHELL,
    COMMAND_ID_MAP_LANATTACKS,
    COMMAND_ID_MAP_PEINJECTOR,
    COMMAND_ID_MAP_MIMIKATZ,
  ].inject({}) {|m1, m2| m1.merge(m2)}
  command_ids = id_map.map {|k, v| "#{k.split('_').map(&:capitalize).join} = #{v},"}
  %Q^
/// <summary>
// This content was generated by a tool @ #{Time.now.utc}
/// </summary>
namespace MSF.Powershell.Meterpreter
{
    public enum CommandId
    {
        #{command_ids.join("\n        ")}
    }
}
  ^
end

def self.method_string_to_command_id(method_string)
  unless COMMAND_ID_MAP.include?(method_string)
    raise ArgumentError, "Unknown Packet command method string: #{method_string}, please report this to the Metasploit team."
  end

  COMMAND_ID_MAP[method_string]
end

def self.command_id_to_method_string(method_int)
  value = COMMAND_ID_MAP.key(method_int)

  if value.nil?
    raise ArgumentError, "Unknown Packet command method integer: #{}, please report this to the Metasploit team."
  end

  value
end


###
#
# Base TLV (Type-Length-Value) class
#
###
class Tlv
  attr_accessor :type, :value, :compress

  HEADER_SIZE = 8

  ##
  #
  # Constructor
  #
  ##

  #
  # Returns an instance of a TLV.
  #
  def initialize(type, value = nil, compress=false)
    @type     = type
    @compress = compress

    if (value != nil)
      if (type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
        if (value.kind_of?(Integer))
          @value = value.to_s
        else
          @value = value.dup
        end
      else
        @value = value
      end
    end
  end

  def inspect
    utype = type ^ TLV_META_TYPE_COMPRESSED
    group = false
    meta = case (utype & TLV_META_MASK)
      when TLV_META_TYPE_STRING; "STRING"
      when TLV_META_TYPE_UINT; "INT"
      when TLV_META_TYPE_RAW; "RAW"
      when TLV_META_TYPE_BOOL; "BOOL"
      when TLV_META_TYPE_QWORD; "QWORD"
      when TLV_META_TYPE_GROUP; group=true; "GROUP"
      when TLV_META_TYPE_COMPLEX; "COMPLEX"
      else; 'unknown-meta-type'
      end
    stype = case type
      when PACKET_TYPE_REQUEST; "Request"
      when PACKET_TYPE_RESPONSE; "Response"
      when TLV_TYPE_REQUEST_ID; "REQUEST-ID"
      when TLV_TYPE_COMMAND_ID; "COMMAND-ID"
      when TLV_TYPE_RESULT; "RESULT"
      when TLV_TYPE_EXCEPTION; "EXCEPTION"
      when TLV_TYPE_STRING; "STRING"
      when TLV_TYPE_UINT; "UINT"
      when TLV_TYPE_BOOL; "BOOL"

      when TLV_TYPE_LENGTH; "LENGTH"
      when TLV_TYPE_DATA; "DATA"
      when TLV_TYPE_FLAGS; "FLAGS"

      when TLV_TYPE_CHANNEL_ID; "CHANNEL-ID"
      when TLV_TYPE_CHANNEL_TYPE; "CHANNEL-TYPE"
      when TLV_TYPE_CHANNEL_DATA; "CHANNEL-DATA"
      when TLV_TYPE_CHANNEL_DATA_GROUP; "CHANNEL-DATA-GROUP"
      when TLV_TYPE_CHANNEL_CLASS; "CHANNEL-CLASS"
      when TLV_TYPE_CHANNEL_PARENTID; "CHANNEL-PARENTID"

      when TLV_TYPE_SEEK_WHENCE; "SEEK-WHENCE"
      when TLV_TYPE_SEEK_OFFSET; "SEEK-OFFSET"
      when TLV_TYPE_SEEK_POS; "SEEK-POS"

      when TLV_TYPE_EXCEPTION_CODE; "EXCEPTION-CODE"
      when TLV_TYPE_EXCEPTION_STRING; "EXCEPTION-STRING"

      when TLV_TYPE_LIBRARY_PATH; "LIBRARY-PATH"
      when TLV_TYPE_TARGET_PATH; "TARGET-PATH"
      when TLV_TYPE_MIGRATE_PID; "MIGRATE-PID"
      when TLV_TYPE_MIGRATE_PAYLOAD; "MIGRATE-PAYLOAD"
      when TLV_TYPE_MIGRATE_ARCH; "MIGRATE-ARCH"
      when TLV_TYPE_MIGRATE_BASE_ADDR; "MIGRATE-BASE-ADDR"
      when TLV_TYPE_MIGRATE_ENTRY_POINT; "MIGRATE-ENTRY-POINT"
      when TLV_TYPE_MIGRATE_STUB; "MIGRATE-STUB"
      when TLV_TYPE_MIGRATE_SOCKET_PATH; "MIGRATE-SOCKET-PATH"
      when TLV_TYPE_LIB_LOADER_NAME; "LIB-LOADER-NAME"
      when TLV_TYPE_LIB_LOADER_ORDINAL; "LIB-LOADER-ORDINAL"
      when TLV_TYPE_TRANS_TYPE; "TRANS-TYPE"
      when TLV_TYPE_TRANS_URL; "TRANS-URL"
      when TLV_TYPE_TRANS_COMM_TIMEOUT; "TRANS-COMM-TIMEOUT"
      when TLV_TYPE_TRANS_SESSION_EXP; "TRANS-SESSION-EXP"
      when TLV_TYPE_TRANS_CERT_HASH; "TRANS-CERT-HASH"
      when TLV_TYPE_TRANS_PROXY_HOST; "TRANS-PROXY-HOST"
      when TLV_TYPE_TRANS_PROXY_USER; "TRANS-PROXY-USER"
      when TLV_TYPE_TRANS_PROXY_PASS; "TRANS-PROXY-PASS"
      when TLV_TYPE_TRANS_RETRY_TOTAL; "TRANS-RETRY-TOTAL"
      when TLV_TYPE_TRANS_RETRY_WAIT; "TRANS-RETRY-WAIT"
      when TLV_TYPE_MACHINE_ID; "MACHINE-ID"
      when TLV_TYPE_UUID; "UUID"
      when TLV_TYPE_SESSION_GUID; "SESSION-GUID"
      when TLV_TYPE_RSA_PUB_KEY; "RSA-PUB-KEY"
      when TLV_TYPE_SYM_KEY_TYPE; "SYM-KEY-TYPE"
      when TLV_TYPE_SYM_KEY; "SYM-KEY"
      when TLV_TYPE_ENC_SYM_KEY; "ENC-SYM-KEY"

      when TLV_TYPE_PIVOT_ID; "PIVOT-ID"
      when TLV_TYPE_PIVOT_STAGE_DATA; "PIVOT-STAGE-DATA"
      when TLV_TYPE_PIVOT_NAMED_PIPE_NAME; "PIVOT-NAMED-PIPE-NAME"

      else; "unknown-#{type}"
      end
    val = value.inspect
    if val.length > 50
      val = val[0,50] + ' ..."'
    end
    group ||= (self.class.to_s =~ /Packet/)
    if group
      tlvs_inspect = "tlvs=[\n"
      @tlvs.each { |t|
        tlvs_inspect << "  #{t.inspect}\n"
      }
      tlvs_inspect << "]"
    else
      tlvs_inspect = "meta=#{meta.ljust(10)} value=#{val}"
    end
    "#<#{self.class} type=#{stype.ljust(15)} #{tlvs_inspect}>"
  end

  ##
  #
  # Conditionals
  #
  ##

  #
  # Checks to see if a TLVs meta type is equivalent to the meta type passed.
  #
  def meta_type?(meta)
    return (self.type & meta == meta)
  end

  #
  # Checks to see if the TLVs type is equivalent to the type passed.
  #
  def type?(type)
    return self.type == type
  end

  #
  # Checks to see if the TLVs value is equivalent to the value passed.
  #
  def value?(value)
    return self.value == value
  end

  ##
  #
  # Serializers
  #
  ##

  #
  # Converts the TLV to raw.
  #
  def to_r
    # Forcibly convert to ASCII-8BIT encoding
    raw = value.to_s.unpack("C*").pack("C*")

    if (self.type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
      raw += "\x00"
    elsif (self.type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT)
      raw = [value].pack("N")
    elsif (self.type & TLV_META_TYPE_QWORD == TLV_META_TYPE_QWORD)
      raw = [ self.htonq( value.to_i ) ].pack("Q<")
    elsif (self.type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL)
      if (value == true)
        raw = [1].pack("c")
      else
        raw = [0].pack("c")
      end
    end

    # check if the tlv is to be compressed...
    if @compress
      raw_uncompressed = raw
      # compress the raw data
      raw_compressed = Rex::Text.zlib_deflate( raw_uncompressed )
      # check we have actually made the raw data smaller...
      # (small blobs often compress slightly larger then the origional)
      # if the compressed data is not smaller, we dont use the compressed data
      if( raw_compressed.length < raw_uncompressed.length )
        # if so, set the TLV's type to indicate compression is used
        self.type = self.type | TLV_META_TYPE_COMPRESSED
        # update the raw data with the uncompressed data length + compressed data
        # (we include the uncompressed data length as the C side will need to know this for decompression)
        raw = [ raw_uncompressed.length ].pack("N") + raw_compressed
      end
    end

    [raw.length + HEADER_SIZE, self.type].pack("NN") + raw
  end

  #
  # Translates the raw format of the TLV into a sanitize version.
  #
  def from_r(raw)
    self.value  = nil

    length, self.type = raw.unpack("NN");

    # check if the tlv value has been compressed...
    if( self.type & TLV_META_TYPE_COMPRESSED == TLV_META_TYPE_COMPRESSED )
      # set this TLV as using compression
      @compress = true
      # remove the TLV_META_TYPE_COMPRESSED flag from the tlv type to restore the
      # tlv type to its origional, allowing for transparent data compression.
      self.type = self.type ^ TLV_META_TYPE_COMPRESSED
      # decompress the compressed data (skipping the length and type DWORD's)
      raw_decompressed = Rex::Text.zlib_inflate( raw[HEADER_SIZE..length-1] )
      # update the length to reflect the decompressed data length (+HEADER_SIZE for the length and type DWORD's)
      length = raw_decompressed.length + HEADER_SIZE
      # update the raw buffer with the new length, decompressed data and updated type.
      raw = [length, self.type].pack("NN") + raw_decompressed
    end

    if (self.type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
      if (raw.length > 0)
        self.value = raw[HEADER_SIZE..length-2]
      else
        self.value = nil
      end
    elsif (self.type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT)
      self.value = raw.unpack("NNN")[2]
    elsif (self.type & TLV_META_TYPE_QWORD == TLV_META_TYPE_QWORD)
      self.value = raw.unpack("NNQ<")[2]
      self.value = self.ntohq( self.value )
    elsif (self.type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL)
      self.value = raw.unpack("NNc")[2]

      if (self.value == 1)
        self.value = true
      else
        self.value = false
      end
    else
      self.value = raw[HEADER_SIZE..length-1]
    end

    length
  end

  protected

  def htonq(value)
    if [1].pack( 's' ) == [1].pack('n')
      return value
    else
      [value].pack('Q<').reverse.unpack('Q<').first
    end
  end

  def ntohq(value)
    htonq(value)
  end

end

###
#
# Group TLVs contain zero or more TLVs
#
###
class GroupTlv < Tlv
  attr_accessor :tlvs

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the group TLV container to the supplied type
  # and creates an empty TLV array.
  #
  def initialize(type)
    super(type)

    self.tlvs = []
  end

  ##
  #
  # Group-based TLV accessors
  #
  ##

  #
  # Enumerates TLVs of the supplied type.
  #
  def each(type = TLV_TYPE_ANY, &block)
    get_tlvs(type).each(&block)
  end

  #
  # Synonym for each.
  #
  def each_tlv(type = TLV_TYPE_ANY, &block)
    each(type, &block)
  end

  #
  # Enumerates TLVs of a supplied type with indexes.
  #
  def each_with_index(type = TLV_TYPE_ANY, &block)
    get_tlvs(type).each_with_index(&block)
  end

  #
  # Synonym for each_with_index.
  #
  def each_tlv_with_index(type = TLV_TYPE_ANY, &block)
    each_with_index(type, block)
  end

  #
  # Returns an array of TLVs for the given type.
  #
  def get_tlvs(type)
    if type == TLV_TYPE_ANY
      self.tlvs
    else
      type_tlvs = []

      self.tlvs.each() { |tlv|
        if (tlv.type?(type))
          type_tlvs << tlv
        end
      }

      type_tlvs
    end
  end

  ##
  #
  # TLV management
  #
  ##

  #
  # Adds a TLV of a given type and value.
  #
  def add_tlv(type, value = nil, replace = false, compress=false)

    # If we should replace any TLVs with the same type...remove them first
    if replace
      each(type) { |tlv|
        if (tlv.type == type)
          self.tlvs.delete(tlv)
        end
      }
    end

    if (type & TLV_META_TYPE_GROUP == TLV_META_TYPE_GROUP)
      tlv = GroupTlv.new(type)
    else
      tlv = Tlv.new(type, value, compress)
    end

    self.tlvs << tlv

    tlv
  end

  #
  # Adds zero or more TLVs to the packet.
  #
  def add_tlvs(tlvs)
    if tlvs
      tlvs.each { |tlv|
        add_tlv(tlv['type'], tlv['value'])
      }
    end
  end

  #
  # Gets the first TLV of a given type.
  #
  def get_tlv(type, index = 0)
    type_tlvs = get_tlvs(type)

    if type_tlvs.length > index
      type_tlvs[index]
    else
      nil
    end

  end

  #
  # Returns the value of a TLV if it exists, otherwise nil.
  #
  def get_tlv_value(type, index = 0)
    tlv = get_tlv(type, index)

    (tlv != nil) ? tlv.value : nil
  end

  #
  # Returns an array of values for all tlvs of type type.
  #
  def get_tlv_values(type)
    get_tlvs(type).collect { |a| a.value }
  end

  #
  # Checks to see if the container has a TLV of a given type.
  #
  def has_tlv?(type)
    get_tlv(type) != nil
  end

  #
  # Zeros out the array of TLVs.
  #
  def reset
    self.tlvs = []
  end

  ##
  #
  # Serializers
  #
  ##

  #
  # Converts all of the TLVs in the TLV array to raw and prefixes them
  # with a container TLV of this instance's TLV type.
  #
  def to_r
    raw = ''

    self.each() { |tlv|
      raw << tlv.to_r
    }

    [raw.length + HEADER_SIZE, self.type].pack("NN") + raw
  end

  #
  # Converts the TLV group container from raw to all of the individual
  # TLVs.
  #
  def from_r(raw)
    offset = HEADER_SIZE

    # Reset the TLVs array
    self.tlvs = []
    self.type = raw.unpack("NN")[1]

    # Enumerate all of the TLVs
    while offset < raw.length-1

      tlv = nil

      # Get the length and type
      length, type = raw[offset..offset+HEADER_SIZE].unpack("NN")

      if (type & TLV_META_TYPE_GROUP == TLV_META_TYPE_GROUP)
        tlv = GroupTlv.new(type)
      else
        tlv = Tlv.new(type)
      end

      tlv.from_r(raw[offset..offset+length])

      # Insert it into the list of TLVs
      tlvs << tlv

      # Move up
      offset += length
    end
  end

end

###
#
# The logical meterpreter packet class
#
###
class Packet < GroupTlv
  attr_accessor :created_at
  attr_accessor :raw
  attr_accessor :session_guid
  attr_accessor :encrypt_flags
  attr_accessor :length

  ##
  #
  # The Packet container itself has a custom header that is slightly different than the
  # typical TLV packets. The header contains the following:
  #
  # XOR KEY        - 4 bytes
  # Session GUID   - 16 bytes
  # Encrypt flags  - 4 bytes
  # Packet length  - 4 bytes
  # Packet type    - 4 bytes
  # Packet data    - X bytes
  #
  # If the encrypt flags are zero, then the Packet data is just straight TLV values as
  # per the normal TLV packet structure.
  #
  # If the encrypt flags are non-zer, then the Packet data is encrypted based on the scheme.
  #
  # Flag == 1 (AES256)
  #    IV             - 16 bytes
  #    Encrypted data - X bytes
  #
  # The key that is required to decrypt the data is stored alongside the session data,
  # and hence when the packet is initially parsed, only the header is accessed. The
  # packet itself will need to be decrypted on the fly at the point that it is required
  # and at that point the decryption key needs to be provided.
  #
  ###

  XOR_KEY_SIZE = 4
  ENCRYPTED_FLAGS_SIZE = 4
  PACKET_LENGTH_SIZE = 4
  PACKET_TYPE_SIZE = 4
  PACKET_HEADER_SIZE = XOR_KEY_SIZE + GUID_SIZE + ENCRYPTED_FLAGS_SIZE + PACKET_LENGTH_SIZE + PACKET_TYPE_SIZE

  AES_IV_SIZE = 16

  ENC_FLAG_NONE   = 0x0
  ENC_FLAG_AES256 = 0x1
  ENC_FLAG_AES128 = 0x2

  ##
  #
  # Factory
  #
  ##

  #
  # Creates a request with the supplied method.
  #
  def Packet.create_request(method = nil)
    Packet.new(PACKET_TYPE_REQUEST, method)
  end

  #
  # Creates a response to a request if one is provided.
  #
  def Packet.create_response(request = nil)
    response_type = PACKET_TYPE_RESPONSE
    method = nil
    id = nil

    if (request)
      if (request.type?(PACKET_TYPE_PLAIN_REQUEST))
        response_type = PACKET_TYPE_PLAIN_RESPONSE
      end

      method = request.method

      if request.has_tlv?(TLV_TYPE_REQUEST_ID)
        id = request.get_tlv_value(TLV_TYPE_REQUEST_ID)
      end
    end

    packet = Packet.new(response_type, method)

    if id
      packet.add_tlv(TLV_TYPE_REQUEST_ID, id)
    end

    packet
  end

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the packet to the supplied packet type and method,
  # if any.  If the packet is a request, a request identifier is
  # created.
  #
  def initialize(type = nil, method = nil)
    super(type)

    if method
      self.method = method
    end

    self.created_at = ::Time.now
    self.raw = ''

    # If it's a request, generate a random request identifier
    if ((type == PACKET_TYPE_REQUEST) ||
        (type == PACKET_TYPE_PLAIN_REQUEST))
      rid = ''

      32.times { |val| rid << rand(10).to_s }

      add_tlv(TLV_TYPE_REQUEST_ID, rid)
    end
  end

  def add_raw(bytes)
    self.raw << bytes
  end

  def raw_bytes_required
    # if we have the xor bytes and length ...
    if self.raw.length >= PACKET_HEADER_SIZE
      # return a value based on the length of the data indicated by
      # the header
      xor_key = self.raw.unpack('a4')[0]
      decoded_bytes = xor_bytes(xor_key, raw[0, PACKET_HEADER_SIZE])
      _, _, _, length, _ = decoded_bytes.unpack('a4a16NNN')
      length + PACKET_HEADER_SIZE - HEADER_SIZE - self.raw.length
    else
      # Otherwise ask for the remaining bytes for the metadata to get the packet length
      # So we can do the rest of the calculation next time
      PACKET_HEADER_SIZE - self.raw.length
    end
  end

  def aes_encrypt(key, data)
    size = key.length * 8
    raise ArgumentError.new('AES key width must be 128 or 256 bits') unless (size == 128 || size == 256)
    # Create the required cipher instance
    aes = OpenSSL::Cipher.new("AES-#{size}-CBC")
    # Generate a truly random IV
    iv = aes.random_iv

    # set up the encryption
    aes.encrypt
    aes.key = key
    aes.iv = iv

    # encrypt and return the IV along with the result
    return iv, aes.update(data) + aes.final
  end

  def aes_decrypt(key, iv, data)
    size = key.length * 8
    raise ArgumentError.new('AES key width must be 128 or 256 bits') unless (size == 128 || size == 256)
    # Create the required cipher instance
    aes = OpenSSL::Cipher.new("AES-#{size}-CBC")
    # Generate a truly random IV

    # set up the encryption
    aes.decrypt
    aes.key = key
    aes.iv = iv

    # decrypt!
    aes.update(data) + aes.final
  end

  #
  # Override the function that creates the raw byte stream for
  # sending so that it generates an XOR key, uses it to scramble
  # the serialized TLV content, and then returns the key plus the
  # scrambled data as the payload.
  #
  def to_r(session_guid = nil, key = nil)
    xor_key = (rand(254) + 1).chr + (rand(254) + 1).chr + (rand(254) + 1).chr + (rand(254) + 1).chr

    raw = (session_guid || NULL_GUID).dup
    tlv_data = GroupTlv.instance_method(:to_r).bind(self).call

    if key && key[:key] && (key[:type] == ENC_FLAG_AES128 || key[:type] == ENC_FLAG_AES256)
      # encrypt the data, but not include the length and type
      iv, ciphertext = aes_encrypt(key[:key], tlv_data[HEADER_SIZE..-1])
      # now manually add the length/type/iv/ciphertext
      raw << [key[:type], iv.length + ciphertext.length + HEADER_SIZE, self.type, iv, ciphertext].pack('NNNA*A*')
    else
      raw << [ENC_FLAG_NONE, tlv_data].pack('NA*')
    end

    # return the xor'd result with the key
    xor_key + xor_bytes(xor_key, raw)
  end

  #
  # Decrypt the packet based on the content of the encryption flags.
  #
  def decrypt_packet(key, encrypt_flags, data)
    # TODO: throw an error if the expected encryption isn't the same as the given
    #       as this could be an indication of hijacking or side-channel packet addition
    #       as highlighted by Justin Steven on github.
    if key && key[:key] && key[:type] && encrypt_flags == key[:type] && (encrypt_flags == ENC_FLAG_AES128 || encrypt_flags == ENC_FLAG_AES256)
      iv = data[0, AES_IV_SIZE]
      aes_decrypt(key[:key], iv, data[iv.length..-1])
    else
      data
    end
  end

  def parse_header!
    xor_key = self.raw.unpack('a4')[0]
    data = xor_bytes(xor_key, self.raw[0..PACKET_HEADER_SIZE])
    _, self.session_guid, self.encrypt_flags, self.length, self.type = data.unpack('a4a16NNN')
  end

  #
  # Override the function that reads from a raw byte stream so
  # that the XORing of data is included in the process prior to
  # passing it on to the default functionality that can parse
  # the TLV values.
  #
  def from_r(key=nil)
    self.parse_header!
    xor_key = self.raw.unpack('a4')[0]
    data = xor_bytes(xor_key, self.raw[PACKET_HEADER_SIZE..-1])
    raw = decrypt_packet(key, self.encrypt_flags, data)
    super([self.length, self.type, raw].pack('NNA*'))
  end

  #
  # Xor a set of bytes with a given XOR key.
  #
  def xor_bytes(xor_key, bytes)
    xor_key = xor_key.bytes
    result = ''
    i = 0
    bytes.each_byte do |b|
      result << (b ^ xor_key[i % xor_key.length]).chr
      i += 1
    end
    result
  end

  ##
  #
  # Conditionals
  #
  ##

  #
  # Checks to see if the packet is a response.
  #
  def response?
    (self.type == PACKET_TYPE_RESPONSE || self.type == PACKET_TYPE_PLAIN_RESPONSE)
  end

  ##
  #
  # Accessors
  #
  ##

  #
  # Checks to see if the packet's method is equal to the supplied method.
  #
  def method?(method)
    (get_tlv_value(TLV_TYPE_COMMAND_ID) == method)
  end

  #
  # Sets the packet's method TLV to the method supplied.
  #
  def method=(method)
    raise ArgumentError.new("Packet.method must be an integer. Current value is #{method}") unless method.is_a?(Integer)
    add_tlv(TLV_TYPE_COMMAND_ID, method, true)
  end

  #
  # Returns the value of the packet's method TLV.
  #
  def method
    get_tlv_value(TLV_TYPE_COMMAND_ID)
  end

  #
  # Checks to see if the packet's result value is equal to the supplied
  # result.
  #
  def result?(result)
    (get_tlv_value(TLV_TYPE_RESULT) == result)
  end

  #
  # Sets the packet's result TLV.
  #
  def result=(result)
    add_tlv(TLV_TYPE_RESULT, result, true)
  end

  #
  # Gets the value of the packet's result TLV.
  #
  def result
    get_tlv_value(TLV_TYPE_RESULT)
  end

  #
  # Gets the value of the packet's request identifier TLV.
  #
  def rid
    get_tlv_value(TLV_TYPE_REQUEST_ID)
  end
end


end; end; end

