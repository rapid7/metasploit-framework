

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


 /* File created by MIDL compiler version 7.00.0500 */
/* at Wed Nov 11 00:29:10 2009
 */
/* Compiler settings for .\PassiveX.idl:
    Oicf, W1, Zp8, env=Win32 (32b run)
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
//@@MIDL_FILE_HEADING(  )

#pragma warning( disable: 4049 )  /* more than 64k source lines */


#ifdef __cplusplus
extern "C"{
#endif 


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, IID_IPassiveX,0x1940F02F,0x41B0,0x4d92,0xBE,0x34,0xDA,0x55,0xD1,0x51,0x89,0x3A);


MIDL_DEFINE_GUID(IID, LIBID_PassiveXCOM,0xCA8B739E,0x450C,0x47bb,0xA5,0x57,0x35,0x79,0xA6,0x33,0xBB,0x5D);


MIDL_DEFINE_GUID(IID, DIID_PassiveXEvents,0x9A427004,0x996C,0x4d39,0xBF,0x55,0xF7,0xEB,0xE0,0xEC,0x62,0x49);


MIDL_DEFINE_GUID(CLSID, CLSID_PassiveX,0xB3AC7307,0xFEAE,0x4e43,0xB2,0xD6,0x16,0x1E,0x68,0xAB,0xA8,0x38);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



