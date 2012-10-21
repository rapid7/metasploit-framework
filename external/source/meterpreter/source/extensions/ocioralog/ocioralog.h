#ifndef _METERPRETER_SOURCE_EXTENSION_OCIORALOG_OCIORALOG_H
#define _METERPRETER_SOURCE_EXTENSION_OCIORALOG_OCIORALOG_H

#define BUF_SIZE 4096

#define TLV_TYPE_EXTENSION_OCIORALOG	0


#define TLV_TYPE_OCIORALOG_HOOK	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_OCIORALOG,		\
				TLV_EXTENSIONS + 2)

#define TLV_TYPE_OCIORALOG_UNHOOK	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_OCIORALOG,		\
				TLV_EXTENSIONS + 3)

#define TLV_TYPE_OCIORALOG_SETLOGFILE	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_OCIORALOG,		\
				TLV_EXTENSIONS + 4)

#define TLV_TYPE_OCIORALOG_GETLOGFILE		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 5)

#define TLV_TYPE_OCIORALOG_HOOKOCISERVERATTACH		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 6)

#define TLV_TYPE_OCIORALOG_HOOKOCISTMTEXECUTE		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 7)

#define TLV_TYPE_OCIORALOG_HOOKOCIATTRSET		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 8)

#define TLV_TYPE_OCIORALOG_UNHOOKOCISERVERATTACH		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 9)

#define TLV_TYPE_OCIORALOG_UNHOOKOCISTMTEXECUTE		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 10)

#define TLV_TYPE_OCIORALOG_UNHOOKOCIATTRSET		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 11)

#define TLV_TYPE_OCIORALOG_GENERIC_RESPONSE		\
		MAKE_CUSTOM_TLV(						\
				TLV_META_TYPE_STRING,			\
				TLV_TYPE_EXTENSION_OCIORALOG,   \
				TLV_EXTENSIONS + 12)

// NEW FUNCTIONS AND DEFINITIONS

// OCI TYPES

#define dvoid void
#define OCIError void
#define OCISvcCtx void
#define OCIStmt void
#define OCISnapshot void
#define OCIServer void
typedef signed int sword;
typedef unsigned int  ub4;
typedef unsigned int sb4;
typedef char* text;


// OCI CONSTANTS
#define OCI_ATTR_USERNAME 22
#define OCI_ATTR_PASSWORD 23
#define OCI_ATTR_SERVER 6

//The exact site of OCI struct fields are highly depends on
//the architecture (x86 vs x64)
#if defined(_M_X64) || defined(__amd64__)
  #include "typedefs_64.h"
#else
  #include "typedefs.h"
#endif


typedef sword (*OCIATTRSET)(dvoid*, ub4, dvoid*, ub4, ub4, OCIError*);
typedef sword (*OCISTMTEXECUTE)(OCISvcCtx*,OCIStmt*,OCIError*,ub4,ub4,const OCISnapshot*, OCISnapshot*,ub4);
typedef sword (*OCISERVERATTACH)(OCIServer*, OCIError*, const text, sb4, ub4);

int logUsernamePassword(OCISvcCtx *svchp);
int logSQLStmt(OCIStmt *stmtp);
int write_log(const char* logfn,char *message);
int DESdecrypt( char *Key, char *Msg, int size, char *res);

void strrep(char *str, char old, char n);

#endif
