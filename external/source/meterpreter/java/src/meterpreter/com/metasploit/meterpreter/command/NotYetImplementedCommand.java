package com.metasploit.meterpreter.command;

import java.io.PrintStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;

/**
 * A command that represents a command that is not yet implemented. It will dump the complete request packet to the error stream and return {@link Command#ERROR_FAILURE}.
 * 
 * @author mihi
 */
public class NotYetImplementedCommand implements Command {

	public static final NotYetImplementedCommand INSTANCE = new NotYetImplementedCommand();

	private Map/* <Integer,String> */typeNames = new HashMap();

	private NotYetImplementedCommand() {
		typeNames.put(new Integer(TLVType.TLV_TYPE_ANY), "TLV_TYPE_ANY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_METHOD), "TLV_TYPE_METHOD");
		typeNames.put(new Integer(TLVType.TLV_TYPE_REQUEST_ID), "TLV_TYPE_REQUEST_ID");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EXCEPTION), "TLV_TYPE_EXCEPTION");
		typeNames.put(new Integer(TLVType.TLV_TYPE_RESULT), "TLV_TYPE_RESULT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_STRING), "TLV_TYPE_STRING");
		typeNames.put(new Integer(TLVType.TLV_TYPE_UINT), "TLV_TYPE_UINT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_BOOL), "TLV_TYPE_BOOL");
		typeNames.put(new Integer(TLVType.TLV_TYPE_LENGTH), "TLV_TYPE_LENGTH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DATA), "TLV_TYPE_DATA");
		typeNames.put(new Integer(TLVType.TLV_TYPE_FLAGS), "TLV_TYPE_FLAGS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CHANNEL_ID), "TLV_TYPE_CHANNEL_ID");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CHANNEL_TYPE), "TLV_TYPE_CHANNEL_TYPE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CHANNEL_DATA), "TLV_TYPE_CHANNEL_DATA");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CHANNEL_DATA_GROUP), "TLV_TYPE_CHANNEL_DATA_GROUP");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CHANNEL_CLASS), "TLV_TYPE_CHANNEL_CLASS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_SEEK_WHENCE), "TLV_TYPE_SEEK_WHENCE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_SEEK_OFFSET), "TLV_TYPE_SEEK_OFFSET");
		typeNames.put(new Integer(TLVType.TLV_TYPE_SEEK_POS), "TLV_TYPE_SEEK_POS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EXCEPTION_CODE), "TLV_TYPE_EXCEPTION_CODE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EXCEPTION_STRING), "TLV_TYPE_EXCEPTION_STRING");
		typeNames.put(new Integer(TLVType.TLV_TYPE_LIBRARY_PATH), "TLV_TYPE_LIBRARY_PATH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_TARGET_PATH), "TLV_TYPE_TARGET_PATH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_MIGRATE_PID), "TLV_TYPE_MIGRATE_PID");
		typeNames.put(new Integer(TLVType.TLV_TYPE_MIGRATE_LEN), "TLV_TYPE_MIGRATE_LEN");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CIPHER_NAME), "TLV_TYPE_CIPHER_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CIPHER_PARAMETERS), "TLV_TYPE_CIPHER_PARAMETERS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_HANDLE), "TLV_TYPE_HANDLE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_INHERIT), "TLV_TYPE_INHERIT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_HANDLE), "TLV_TYPE_PROCESS_HANDLE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_THREAD_HANDLE), "TLV_TYPE_THREAD_HANDLE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DIRECTORY_PATH), "TLV_TYPE_DIRECTORY_PATH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_FILE_NAME), "TLV_TYPE_FILE_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_FILE_PATH), "TLV_TYPE_FILE_PATH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_FILE_MODE), "TLV_TYPE_FILE_MODE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_STAT_BUF), "TLV_TYPE_STAT_BUF");
		typeNames.put(new Integer(TLVType.TLV_TYPE_HOST_NAME), "TLV_TYPE_HOST_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PORT), "TLV_TYPE_PORT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_MTU), "TLV_TYPE_MTU");
		typeNames.put(new Integer(TLVType.TLV_TYPE_INTERFACE_INDEX), "TLV_TYPE_INTERFACE_INDEX");
		typeNames.put(new Integer(TLVType.TLV_TYPE_SUBNET), "TLV_TYPE_SUBNET");
		typeNames.put(new Integer(TLVType.TLV_TYPE_NETMASK), "TLV_TYPE_NETMASK");
		typeNames.put(new Integer(TLVType.TLV_TYPE_GATEWAY), "TLV_TYPE_GATEWAY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_NETWORK_ROUTE), "TLV_TYPE_NETWORK_ROUTE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IP_PREFIX), "TLV_TYPE_IP_PREFIX");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IP), "TLV_TYPE_IP");
		typeNames.put(new Integer(TLVType.TLV_TYPE_MAC_ADDRESS), "TLV_TYPE_MAC_ADDRESS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_MAC_NAME), "TLV_TYPE_MAC_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_NETWORK_INTERFACE), "TLV_TYPE_NETWORK_INTERFACE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IP6_SCOPE), "TLV_TYPE_IP6_SCOPE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_SUBNET_STRING), "TLV_TYPE_SUBNET_STRING");
		typeNames.put(new Integer(TLVType.TLV_TYPE_NETMASK_STRING), "TLV_TYPE_NETMASK_STRING");
		typeNames.put(new Integer(TLVType.TLV_TYPE_GATEWAY_STRING), "TLV_TYPE_GATEWAY_STRING");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PEER_HOST), "TLV_TYPE_PEER_HOST");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PEER_PORT), "TLV_TYPE_PEER_PORT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_LOCAL_HOST), "TLV_TYPE_LOCAL_HOST");
		typeNames.put(new Integer(TLVType.TLV_TYPE_LOCAL_PORT), "TLV_TYPE_LOCAL_PORT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CONNECT_RETRIES), "TLV_TYPE_CONNECT_RETRIES");
		typeNames.put(new Integer(TLVType.TLV_TYPE_SHUTDOWN_HOW), "TLV_TYPE_SHUTDOWN_HOW");
		typeNames.put(new Integer(TLVType.TLV_TYPE_HKEY), "TLV_TYPE_HKEY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_ROOT_KEY), "TLV_TYPE_ROOT_KEY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_BASE_KEY), "TLV_TYPE_BASE_KEY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PERMISSION), "TLV_TYPE_PERMISSION");
		typeNames.put(new Integer(TLVType.TLV_TYPE_KEY_NAME), "TLV_TYPE_KEY_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_VALUE_NAME), "TLV_TYPE_VALUE_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_VALUE_TYPE), "TLV_TYPE_VALUE_TYPE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_VALUE_DATA), "TLV_TYPE_VALUE_DATA");
		typeNames.put(new Integer(TLVType.TLV_TYPE_COMPUTER_NAME), "TLV_TYPE_COMPUTER_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_OS_NAME), "TLV_TYPE_OS_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_USER_NAME), "TLV_TYPE_USER_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_BASE_ADDRESS), "TLV_TYPE_BASE_ADDRESS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_ALLOCATION_TYPE), "TLV_TYPE_ALLOCATION_TYPE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROTECTION), "TLV_TYPE_PROTECTION");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_PERMS), "TLV_TYPE_PROCESS_PERMS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_MEMORY), "TLV_TYPE_PROCESS_MEMORY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_ALLOC_BASE_ADDRESS), "TLV_TYPE_ALLOC_BASE_ADDRESS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_MEMORY_STATE), "TLV_TYPE_MEMORY_STATE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_MEMORY_TYPE), "TLV_TYPE_MEMORY_TYPE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_ALLOC_PROTECTION), "TLV_TYPE_ALLOC_PROTECTION");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PID), "TLV_TYPE_PID");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_NAME), "TLV_TYPE_PROCESS_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_PATH), "TLV_TYPE_PROCESS_PATH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_GROUP), "TLV_TYPE_PROCESS_GROUP");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_FLAGS), "TLV_TYPE_PROCESS_FLAGS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCESS_ARGUMENTS), "TLV_TYPE_PROCESS_ARGUMENTS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IMAGE_FILE), "TLV_TYPE_IMAGE_FILE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IMAGE_FILE_PATH), "TLV_TYPE_IMAGE_FILE_PATH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCEDURE_NAME), "TLV_TYPE_PROCEDURE_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_PROCEDURE_ADDRESS), "TLV_TYPE_PROCEDURE_ADDRESS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IMAGE_BASE), "TLV_TYPE_IMAGE_BASE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IMAGE_GROUP), "TLV_TYPE_IMAGE_GROUP");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IMAGE_NAME), "TLV_TYPE_IMAGE_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_THREAD_ID), "TLV_TYPE_THREAD_ID");
		typeNames.put(new Integer(TLVType.TLV_TYPE_THREAD_PERMS), "TLV_TYPE_THREAD_PERMS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EXIT_CODE), "TLV_TYPE_EXIT_CODE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_ENTRY_POINT), "TLV_TYPE_ENTRY_POINT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_ENTRY_PARAMETER), "TLV_TYPE_ENTRY_PARAMETER");
		typeNames.put(new Integer(TLVType.TLV_TYPE_CREATION_FLAGS), "TLV_TYPE_CREATION_FLAGS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_REGISTER_NAME), "TLV_TYPE_REGISTER_NAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_REGISTER_SIZE), "TLV_TYPE_REGISTER_SIZE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_REGISTER_VALUE_32), "TLV_TYPE_REGISTER_VALUE_32");
		typeNames.put(new Integer(TLVType.TLV_TYPE_REGISTER), "TLV_TYPE_REGISTER");
		typeNames.put(new Integer(TLVType.TLV_TYPE_IDLE_TIME), "TLV_TYPE_IDLE_TIME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_KEYS_DUMP), "TLV_TYPE_KEYS_DUMP");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DESKTOP), "TLV_TYPE_DESKTOP");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_SOURCENAME), "TLV_TYPE_EVENT_SOURCENAME");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_HANDLE), "TLV_TYPE_EVENT_HANDLE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_NUMRECORDS), "TLV_TYPE_EVENT_NUMRECORDS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_READFLAGS), "TLV_TYPE_EVENT_READFLAGS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_RECORDOFFSET), "TLV_TYPE_EVENT_RECORDOFFSET");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_RECORDNUMBER), "TLV_TYPE_EVENT_RECORDNUMBER");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_TIMEGENERATED), "TLV_TYPE_EVENT_TIMEGENERATED");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_TIMEWRITTEN), "TLV_TYPE_EVENT_TIMEWRITTEN");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_ID), "TLV_TYPE_EVENT_ID");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_TYPE), "TLV_TYPE_EVENT_TYPE");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_CATEGORY), "TLV_TYPE_EVENT_CATEGORY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_STRING), "TLV_TYPE_EVENT_STRING");
		typeNames.put(new Integer(TLVType.TLV_TYPE_EVENT_DATA), "TLV_TYPE_EVENT_DATA");
		typeNames.put(new Integer(TLVType.TLV_TYPE_POWER_FLAGS), "TLV_TYPE_POWER_FLAGS");
		typeNames.put(new Integer(TLVType.TLV_TYPE_POWER_REASON), "TLV_TYPE_POWER_REASON");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT), "TLV_TYPE_DESKTOP_SCREENSHOT");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY), "TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_LENGTH), "TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_LENGTH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_BUFFER), "TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_BUFFER");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_LENGTH), "TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_LENGTH");
		typeNames.put(new Integer(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_BUFFER), "TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_BUFFER");
	}

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		meterpreter.getErrorStream().println("Unknown request detected:");
		dumpTLV(meterpreter.getErrorStream(), request);
		return ERROR_FAILURE;
	}

	private void dumpTLV(PrintStream errorStream, TLVPacket request) {
		for (Iterator it = request.getTypeOrder().iterator(); it.hasNext();) {
			int type = ((Integer) it.next()).intValue();
			int restType = type;
			String typePrefix = "";
			if ((type & TLVPacket.TLV_META_TYPE_COMPRESSED) != 0) {
				typePrefix = "Compressed ";
				restType ^= TLVPacket.TLV_META_TYPE_COMPRESSED;
			}
			String typeName = (String) typeNames.get(new Integer(restType));

			Object typeValue = request.getValue(type);
			if (typeName == null)
				typeName = "0x" + Integer.toHexString(type).toUpperCase();
			if (typeValue instanceof byte[]) {
				typeValue = "(raw data, " + ((byte[]) typeValue).length + " bytes)";
			}
			errorStream.println("\t" + typePrefix + typeName + " = " + typeValue);
		}
	}
}
