package com.metasploit.meterpreter;

/**
 * All defined TLV types.
 * 
 * TLV meta types are defined in the {@link TLVPacket} class.
 * 
 * @author mihi
 */
public interface TLVType {

	// TLV Specific Types
	public static final int TLV_TYPE_ANY = TLVPacket.TLV_META_TYPE_NONE | 0;
	public static final int TLV_TYPE_METHOD = TLVPacket.TLV_META_TYPE_STRING | 1;
	public static final int TLV_TYPE_REQUEST_ID = TLVPacket.TLV_META_TYPE_STRING | 2;
	public static final int TLV_TYPE_EXCEPTION = TLVPacket.TLV_META_TYPE_GROUP | 3;
	public static final int TLV_TYPE_RESULT = TLVPacket.TLV_META_TYPE_UINT | 4;

	public static final int TLV_TYPE_STRING = TLVPacket.TLV_META_TYPE_STRING | 10;
	public static final int TLV_TYPE_UINT = TLVPacket.TLV_META_TYPE_UINT | 11;
	public static final int TLV_TYPE_BOOL = TLVPacket.TLV_META_TYPE_BOOL | 12;

	public static final int TLV_TYPE_LENGTH = TLVPacket.TLV_META_TYPE_UINT | 25;
	public static final int TLV_TYPE_DATA = TLVPacket.TLV_META_TYPE_RAW | 26;
	public static final int TLV_TYPE_FLAGS = TLVPacket.TLV_META_TYPE_UINT | 27;

	public static final int TLV_TYPE_CHANNEL_ID = TLVPacket.TLV_META_TYPE_UINT | 50;
	public static final int TLV_TYPE_CHANNEL_TYPE = TLVPacket.TLV_META_TYPE_STRING | 51;
	public static final int TLV_TYPE_CHANNEL_DATA = TLVPacket.TLV_META_TYPE_RAW | 52;
	public static final int TLV_TYPE_CHANNEL_DATA_GROUP = TLVPacket.TLV_META_TYPE_GROUP | 53;
	public static final int TLV_TYPE_CHANNEL_CLASS = TLVPacket.TLV_META_TYPE_UINT | 54;
	public static final int TLV_TYPE_CHANNEL_PARENTID = TLVPacket.TLV_META_TYPE_UINT | 55;

	public static final int TLV_TYPE_SEEK_WHENCE = TLVPacket.TLV_META_TYPE_UINT | 70;
	public static final int TLV_TYPE_SEEK_OFFSET = TLVPacket.TLV_META_TYPE_UINT | 71;
	public static final int TLV_TYPE_SEEK_POS = TLVPacket.TLV_META_TYPE_UINT | 72;

	public static final int TLV_TYPE_EXCEPTION_CODE = TLVPacket.TLV_META_TYPE_UINT | 300;
	public static final int TLV_TYPE_EXCEPTION_STRING = TLVPacket.TLV_META_TYPE_STRING | 301;

	public static final int TLV_TYPE_LIBRARY_PATH = TLVPacket.TLV_META_TYPE_STRING | 400;
	public static final int TLV_TYPE_TARGET_PATH = TLVPacket.TLV_META_TYPE_STRING | 401;
	public static final int TLV_TYPE_MIGRATE_PID = TLVPacket.TLV_META_TYPE_UINT | 402;
	public static final int TLV_TYPE_MIGRATE_LEN = TLVPacket.TLV_META_TYPE_UINT | 403;

	public static final int TLV_TYPE_CIPHER_NAME = TLVPacket.TLV_META_TYPE_STRING | 500;
	public static final int TLV_TYPE_CIPHER_PARAMETERS = TLVPacket.TLV_META_TYPE_GROUP | 501;

	// General
	public static final int TLV_TYPE_HANDLE = TLVPacket.TLV_META_TYPE_UINT | 600;
	public static final int TLV_TYPE_INHERIT = TLVPacket.TLV_META_TYPE_BOOL | 601;
	public static final int TLV_TYPE_PROCESS_HANDLE = TLVPacket.TLV_META_TYPE_UINT | 630;
	public static final int TLV_TYPE_THREAD_HANDLE = TLVPacket.TLV_META_TYPE_UINT | 631;

	// Fs
	public static final int TLV_TYPE_DIRECTORY_PATH = TLVPacket.TLV_META_TYPE_STRING | 1200;
	public static final int TLV_TYPE_FILE_NAME = TLVPacket.TLV_META_TYPE_STRING | 1201;
	public static final int TLV_TYPE_FILE_PATH = TLVPacket.TLV_META_TYPE_STRING | 1202;
	public static final int TLV_TYPE_FILE_MODE = TLVPacket.TLV_META_TYPE_STRING | 1203;
	public static final int TLV_TYPE_STAT_BUF = TLVPacket.TLV_META_TYPE_COMPLEX | 1220;

	// Net
	public static final int TLV_TYPE_HOST_NAME = TLVPacket.TLV_META_TYPE_STRING | 1400;
	public static final int TLV_TYPE_PORT = TLVPacket.TLV_META_TYPE_UINT | 1401;

	public static final int TLV_TYPE_SUBNET = TLVPacket.TLV_META_TYPE_RAW | 1420;
	public static final int TLV_TYPE_NETMASK = TLVPacket.TLV_META_TYPE_RAW | 1421;
	public static final int TLV_TYPE_GATEWAY = TLVPacket.TLV_META_TYPE_RAW | 1422;
	public static final int TLV_TYPE_NETWORK_ROUTE = TLVPacket.TLV_META_TYPE_GROUP | 1423;

	public static final int TLV_TYPE_IP = TLVPacket.TLV_META_TYPE_RAW | 1430;
	public static final int TLV_TYPE_MAC_ADDRESS = TLVPacket.TLV_META_TYPE_RAW | 1431;
	public static final int TLV_TYPE_MAC_NAME = TLVPacket.TLV_META_TYPE_STRING | 1432;
	public static final int TLV_TYPE_NETWORK_INTERFACE = TLVPacket.TLV_META_TYPE_GROUP | 1433;

	public static final int TLV_TYPE_SUBNET_STRING = TLVPacket.TLV_META_TYPE_STRING | 1440;
	public static final int TLV_TYPE_NETMASK_STRING = TLVPacket.TLV_META_TYPE_STRING | 1441;
	public static final int TLV_TYPE_GATEWAY_STRING = TLVPacket.TLV_META_TYPE_STRING | 1442;

	// Socket
	public static final int TLV_TYPE_PEER_HOST = TLVPacket.TLV_META_TYPE_STRING | 1500;
	public static final int TLV_TYPE_PEER_PORT = TLVPacket.TLV_META_TYPE_UINT | 1501;
	public static final int TLV_TYPE_LOCAL_HOST = TLVPacket.TLV_META_TYPE_STRING | 1502;
	public static final int TLV_TYPE_LOCAL_PORT = TLVPacket.TLV_META_TYPE_UINT | 1503;
	public static final int TLV_TYPE_CONNECT_RETRIES = TLVPacket.TLV_META_TYPE_UINT | 1504;

	public static final int TLV_TYPE_SHUTDOWN_HOW = TLVPacket.TLV_META_TYPE_UINT | 1530;

	// Registry
	public static final int TLV_TYPE_HKEY = TLVPacket.TLV_META_TYPE_UINT | 1000;
	public static final int TLV_TYPE_ROOT_KEY = TLV_TYPE_HKEY;
	public static final int TLV_TYPE_BASE_KEY = TLVPacket.TLV_META_TYPE_STRING | 1001;
	public static final int TLV_TYPE_PERMISSION = TLVPacket.TLV_META_TYPE_UINT | 1002;
	public static final int TLV_TYPE_KEY_NAME = TLVPacket.TLV_META_TYPE_STRING | 1003;
	public static final int TLV_TYPE_VALUE_NAME = TLVPacket.TLV_META_TYPE_STRING | 1010;
	public static final int TLV_TYPE_VALUE_TYPE = TLVPacket.TLV_META_TYPE_UINT | 1011;
	public static final int TLV_TYPE_VALUE_DATA = TLVPacket.TLV_META_TYPE_RAW | 1012;

	// Config
	public static final int TLV_TYPE_COMPUTER_NAME = TLVPacket.TLV_META_TYPE_STRING | 1040;
	public static final int TLV_TYPE_OS_NAME = TLVPacket.TLV_META_TYPE_STRING | 1041;
	public static final int TLV_TYPE_USER_NAME = TLVPacket.TLV_META_TYPE_STRING | 1042;

	// Process
	public static final int TLV_TYPE_BASE_ADDRESS = TLVPacket.TLV_META_TYPE_UINT | 2000;
	public static final int TLV_TYPE_ALLOCATION_TYPE = TLVPacket.TLV_META_TYPE_UINT | 2001;
	public static final int TLV_TYPE_PROTECTION = TLVPacket.TLV_META_TYPE_UINT | 2002;
	public static final int TLV_TYPE_PROCESS_PERMS = TLVPacket.TLV_META_TYPE_UINT | 2003;
	public static final int TLV_TYPE_PROCESS_MEMORY = TLVPacket.TLV_META_TYPE_RAW | 2004;
	public static final int TLV_TYPE_ALLOC_BASE_ADDRESS = TLVPacket.TLV_META_TYPE_UINT | 2005;
	public static final int TLV_TYPE_MEMORY_STATE = TLVPacket.TLV_META_TYPE_UINT | 2006;
	public static final int TLV_TYPE_MEMORY_TYPE = TLVPacket.TLV_META_TYPE_UINT | 2007;
	public static final int TLV_TYPE_ALLOC_PROTECTION = TLVPacket.TLV_META_TYPE_UINT | 2008;
	public static final int TLV_TYPE_PID = TLVPacket.TLV_META_TYPE_UINT | 2300;
	public static final int TLV_TYPE_PROCESS_NAME = TLVPacket.TLV_META_TYPE_STRING | 2301;
	public static final int TLV_TYPE_PROCESS_PATH = TLVPacket.TLV_META_TYPE_STRING | 2302;
	public static final int TLV_TYPE_PROCESS_GROUP = TLVPacket.TLV_META_TYPE_GROUP | 2303;
	public static final int TLV_TYPE_PROCESS_FLAGS = TLVPacket.TLV_META_TYPE_UINT | 2304;
	public static final int TLV_TYPE_PROCESS_ARGUMENTS = TLVPacket.TLV_META_TYPE_STRING | 2305;

	public static final int TLV_TYPE_IMAGE_FILE = TLVPacket.TLV_META_TYPE_STRING | 2400;
	public static final int TLV_TYPE_IMAGE_FILE_PATH = TLVPacket.TLV_META_TYPE_STRING | 2401;
	public static final int TLV_TYPE_PROCEDURE_NAME = TLVPacket.TLV_META_TYPE_STRING | 2402;
	public static final int TLV_TYPE_PROCEDURE_ADDRESS = TLVPacket.TLV_META_TYPE_UINT | 2403;
	public static final int TLV_TYPE_IMAGE_BASE = TLVPacket.TLV_META_TYPE_UINT | 2404;
	public static final int TLV_TYPE_IMAGE_GROUP = TLVPacket.TLV_META_TYPE_GROUP | 2405;
	public static final int TLV_TYPE_IMAGE_NAME = TLVPacket.TLV_META_TYPE_STRING | 2406;

	public static final int TLV_TYPE_THREAD_ID = TLVPacket.TLV_META_TYPE_UINT | 2500;
	public static final int TLV_TYPE_THREAD_PERMS = TLVPacket.TLV_META_TYPE_UINT | 2502;
	public static final int TLV_TYPE_EXIT_CODE = TLVPacket.TLV_META_TYPE_UINT | 2510;
	public static final int TLV_TYPE_ENTRY_POINT = TLVPacket.TLV_META_TYPE_UINT | 2511;
	public static final int TLV_TYPE_ENTRY_PARAMETER = TLVPacket.TLV_META_TYPE_UINT | 2512;
	public static final int TLV_TYPE_CREATION_FLAGS = TLVPacket.TLV_META_TYPE_UINT | 2513;

	public static final int TLV_TYPE_REGISTER_NAME = TLVPacket.TLV_META_TYPE_STRING | 2540;
	public static final int TLV_TYPE_REGISTER_SIZE = TLVPacket.TLV_META_TYPE_UINT | 2541;
	public static final int TLV_TYPE_REGISTER_VALUE_32 = TLVPacket.TLV_META_TYPE_UINT | 2542;
	public static final int TLV_TYPE_REGISTER = TLVPacket.TLV_META_TYPE_GROUP | 2550;

	// Ui
	public static final int TLV_TYPE_IDLE_TIME = TLVPacket.TLV_META_TYPE_UINT | 3000;
	public static final int TLV_TYPE_KEYS_DUMP = TLVPacket.TLV_META_TYPE_STRING | 3001;
	public static final int TLV_TYPE_DESKTOP = TLVPacket.TLV_META_TYPE_STRING | 3002;

	// Event Log
	public static final int TLV_TYPE_EVENT_SOURCENAME = TLVPacket.TLV_META_TYPE_STRING | 4000;
	public static final int TLV_TYPE_EVENT_HANDLE = TLVPacket.TLV_META_TYPE_UINT | 4001;
	public static final int TLV_TYPE_EVENT_NUMRECORDS = TLVPacket.TLV_META_TYPE_UINT | 4002;

	public static final int TLV_TYPE_EVENT_READFLAGS = TLVPacket.TLV_META_TYPE_UINT | 4003;
	public static final int TLV_TYPE_EVENT_RECORDOFFSET = TLVPacket.TLV_META_TYPE_UINT | 4004;

	public static final int TLV_TYPE_EVENT_RECORDNUMBER = TLVPacket.TLV_META_TYPE_UINT | 4006;
	public static final int TLV_TYPE_EVENT_TIMEGENERATED = TLVPacket.TLV_META_TYPE_UINT | 4007;
	public static final int TLV_TYPE_EVENT_TIMEWRITTEN = TLVPacket.TLV_META_TYPE_UINT | 4008;
	public static final int TLV_TYPE_EVENT_ID = TLVPacket.TLV_META_TYPE_UINT | 4009;
	public static final int TLV_TYPE_EVENT_TYPE = TLVPacket.TLV_META_TYPE_UINT | 4010;
	public static final int TLV_TYPE_EVENT_CATEGORY = TLVPacket.TLV_META_TYPE_UINT | 4011;
	public static final int TLV_TYPE_EVENT_STRING = TLVPacket.TLV_META_TYPE_STRING | 4012;
	public static final int TLV_TYPE_EVENT_DATA = TLVPacket.TLV_META_TYPE_RAW | 4013;

	// Power
	public static final int TLV_TYPE_POWER_FLAGS = TLVPacket.TLV_META_TYPE_UINT | 4100;
	public static final int TLV_TYPE_POWER_REASON = TLVPacket.TLV_META_TYPE_UINT | 4101;

	// Screenshot
	public static final int TLV_TYPE_DESKTOP_SCREENSHOT = TLVPacket.TLV_META_TYPE_RAW | 3002;
	public static final int TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY = TLVPacket.TLV_META_TYPE_UINT | 3008;
	public static final int TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_LENGTH = TLVPacket.TLV_META_TYPE_UINT | 3009;
	public static final int TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_BUFFER = TLVPacket.TLV_META_TYPE_STRING | 3010;
	public static final int TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_LENGTH = TLVPacket.TLV_META_TYPE_UINT | 3011;
	public static final int TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_BUFFER = TLVPacket.TLV_META_TYPE_STRING | 3012;
}
