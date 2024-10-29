

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


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


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __PassiveX_h__
#define __PassiveX_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IPassiveX_FWD_DEFINED__
#define __IPassiveX_FWD_DEFINED__
typedef interface IPassiveX IPassiveX;
#endif 	/* __IPassiveX_FWD_DEFINED__ */


#ifndef __PassiveXEvents_FWD_DEFINED__
#define __PassiveXEvents_FWD_DEFINED__
typedef interface PassiveXEvents PassiveXEvents;
#endif 	/* __PassiveXEvents_FWD_DEFINED__ */


#ifndef __PassiveX_FWD_DEFINED__
#define __PassiveX_FWD_DEFINED__

#ifdef __cplusplus
typedef class PassiveX PassiveX;
#else
typedef struct PassiveX PassiveX;
#endif /* __cplusplus */

#endif 	/* __PassiveX_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_PassiveX_0000_0000 */
/* [local] */ 


enum PassiveXProperties
    {	PASSIVEX_PROPERTY_HTTP_HOST	= 1,
	PASSIVEX_PROPERTY_HTTP_PORT	= 2,
	PASSIVEX_PROPERTY_HTTP_SID	= 4,
	PASSIVEX_PROPERTY_HTTP_URI_BASE	= 5,
	PASSIVEX_PROPERTY_DOWNLOAD_SECOND_STAGE	= 3
    } ;


extern RPC_IF_HANDLE __MIDL_itf_PassiveX_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_PassiveX_0000_0000_v0_0_s_ifspec;

#ifndef __IPassiveX_INTERFACE_DEFINED__
#define __IPassiveX_INTERFACE_DEFINED__

/* interface IPassiveX */
/* [dual][unique][helpstring][uuid][object] */ 


EXTERN_C const IID IID_IPassiveX;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("1940F02F-41B0-4d92-BE34-DA55D151893A")
    IPassiveX : public IDispatch
    {
    public:
        virtual /* [id][propput] */ HRESULT STDMETHODCALLTYPE put_HttpHost( 
            /* [in] */ BSTR host) = 0;
        
        virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_HttpHost( 
            /* [retval][out] */ BSTR *host) = 0;
        
        virtual /* [id][propput] */ HRESULT STDMETHODCALLTYPE put_HttpSid( 
            /* [in] */ BSTR sid) = 0;
        
        virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_HttpSid( 
            /* [retval][out] */ BSTR *sid) = 0;
        
        virtual /* [id][propput] */ HRESULT STDMETHODCALLTYPE put_HttpUriBase( 
            /* [in] */ BSTR base) = 0;
        
        virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_HttpUriBase( 
            /* [retval][out] */ BSTR *base) = 0;
        
        virtual /* [id][propput] */ HRESULT STDMETHODCALLTYPE put_HttpPort( 
            /* [in] */ ULONG port) = 0;
        
        virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_HttpPort( 
            /* [retval][out] */ ULONG *port) = 0;
        
        virtual /* [id][propput] */ HRESULT STDMETHODCALLTYPE put_DownloadSecondStage( 
            /* [in] */ ULONG na) = 0;
        
        virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_DownloadSecondStage( 
            /* [retval][out] */ ULONG *na) = 0;
        
    };
    
#else 	/* C style interface */

    typedef struct IPassiveXVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IPassiveX * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IPassiveX * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IPassiveX * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IPassiveX * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IPassiveX * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IPassiveX * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IPassiveX * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);
        
        /* [id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_HttpHost )( 
            IPassiveX * This,
            /* [in] */ BSTR host);
        
        /* [id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_HttpHost )( 
            IPassiveX * This,
            /* [retval][out] */ BSTR *host);
        
        /* [id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_HttpSid )( 
            IPassiveX * This,
            /* [in] */ BSTR sid);
        
        /* [id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_HttpSid )( 
            IPassiveX * This,
            /* [retval][out] */ BSTR *sid);
        
        /* [id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_HttpUriBase )( 
            IPassiveX * This,
            /* [in] */ BSTR base);
        
        /* [id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_HttpUriBase )( 
            IPassiveX * This,
            /* [retval][out] */ BSTR *base);
        
        /* [id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_HttpPort )( 
            IPassiveX * This,
            /* [in] */ ULONG port);
        
        /* [id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_HttpPort )( 
            IPassiveX * This,
            /* [retval][out] */ ULONG *port);
        
        /* [id][propput] */ HRESULT ( STDMETHODCALLTYPE *put_DownloadSecondStage )( 
            IPassiveX * This,
            /* [in] */ ULONG na);
        
        /* [id][propget] */ HRESULT ( STDMETHODCALLTYPE *get_DownloadSecondStage )( 
            IPassiveX * This,
            /* [retval][out] */ ULONG *na);
        
        END_INTERFACE
    } IPassiveXVtbl;

    interface IPassiveX
    {
        CONST_VTBL struct IPassiveXVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IPassiveX_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IPassiveX_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IPassiveX_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IPassiveX_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IPassiveX_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IPassiveX_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IPassiveX_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define IPassiveX_put_HttpHost(This,host)	\
    ( (This)->lpVtbl -> put_HttpHost(This,host) ) 

#define IPassiveX_get_HttpHost(This,host)	\
    ( (This)->lpVtbl -> get_HttpHost(This,host) ) 

#define IPassiveX_put_HttpSid(This,sid)	\
    ( (This)->lpVtbl -> put_HttpSid(This,sid) ) 

#define IPassiveX_get_HttpSid(This,sid)	\
    ( (This)->lpVtbl -> get_HttpSid(This,sid) ) 

#define IPassiveX_put_HttpUriBase(This,base)	\
    ( (This)->lpVtbl -> put_HttpUriBase(This,base) ) 

#define IPassiveX_get_HttpUriBase(This,base)	\
    ( (This)->lpVtbl -> get_HttpUriBase(This,base) ) 

#define IPassiveX_put_HttpPort(This,port)	\
    ( (This)->lpVtbl -> put_HttpPort(This,port) ) 

#define IPassiveX_get_HttpPort(This,port)	\
    ( (This)->lpVtbl -> get_HttpPort(This,port) ) 

#define IPassiveX_put_DownloadSecondStage(This,na)	\
    ( (This)->lpVtbl -> put_DownloadSecondStage(This,na) ) 

#define IPassiveX_get_DownloadSecondStage(This,na)	\
    ( (This)->lpVtbl -> get_DownloadSecondStage(This,na) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IPassiveX_INTERFACE_DEFINED__ */



#ifndef __PassiveXCOM_LIBRARY_DEFINED__
#define __PassiveXCOM_LIBRARY_DEFINED__

/* library PassiveXCOM */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_PassiveXCOM;

#ifndef __PassiveXEvents_DISPINTERFACE_DEFINED__
#define __PassiveXEvents_DISPINTERFACE_DEFINED__

/* dispinterface PassiveXEvents */
/* [helpstring][uuid] */ 


EXTERN_C const IID DIID_PassiveXEvents;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("9A427004-996C-4d39-BF55-F7EBE0EC6249")
    PassiveXEvents : public IDispatch
    {
    };
    
#else 	/* C style interface */

    typedef struct PassiveXEventsVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            PassiveXEvents * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            PassiveXEvents * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            PassiveXEvents * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            PassiveXEvents * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            PassiveXEvents * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            PassiveXEvents * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            PassiveXEvents * This,
            /* [in] */ DISPID dispIdMember,
            /* [in] */ REFIID riid,
            /* [in] */ LCID lcid,
            /* [in] */ WORD wFlags,
            /* [out][in] */ DISPPARAMS *pDispParams,
            /* [out] */ VARIANT *pVarResult,
            /* [out] */ EXCEPINFO *pExcepInfo,
            /* [out] */ UINT *puArgErr);
        
        END_INTERFACE
    } PassiveXEventsVtbl;

    interface PassiveXEvents
    {
        CONST_VTBL struct PassiveXEventsVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define PassiveXEvents_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define PassiveXEvents_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define PassiveXEvents_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define PassiveXEvents_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define PassiveXEvents_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define PassiveXEvents_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define PassiveXEvents_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */


#endif 	/* __PassiveXEvents_DISPINTERFACE_DEFINED__ */


EXTERN_C const CLSID CLSID_PassiveX;

#ifdef __cplusplus

class DECLSPEC_UUID("B3AC7307-FEAE-4e43-B2D6-161E68ABA838")
PassiveX;
#endif
#endif /* __PassiveXCOM_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

unsigned long             __RPC_USER  BSTR_UserSize(     unsigned long *, unsigned long            , BSTR * ); 
unsigned char * __RPC_USER  BSTR_UserMarshal(  unsigned long *, unsigned char *, BSTR * ); 
unsigned char * __RPC_USER  BSTR_UserUnmarshal(unsigned long *, unsigned char *, BSTR * ); 
void                      __RPC_USER  BSTR_UserFree(     unsigned long *, BSTR * ); 

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


