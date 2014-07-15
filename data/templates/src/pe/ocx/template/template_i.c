

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


 /* File created by MIDL compiler version 8.00.0602 */
/* at Fri Aug 30 02:39:05 2013
 */
/* Compiler settings for template.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.00.0602 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

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

MIDL_DEFINE_GUID(IID, LIBID_templateLib,0xF8F555A6,0xC743,0x4334,0x8B,0xE9,0xCC,0x4C,0xCC,0x57,0xCD,0x75);


MIDL_DEFINE_GUID(IID, DIID__Dtemplate,0x3B0404BF,0xD58D,0x46D0,0xB3,0x01,0x86,0xA1,0xBA,0xD0,0xD9,0xCE);


MIDL_DEFINE_GUID(IID, DIID__DtemplateEvents,0x06DAD5F2,0x4719,0x4FF1,0xAA,0x60,0x4C,0x2E,0x8F,0x6D,0x59,0xD7);


MIDL_DEFINE_GUID(CLSID, CLSID_template,0x56C04F88,0x9E36,0x434B,0x82,0xA3,0xD5,0x52,0xB8,0x1A,0x8C,0xB9);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



