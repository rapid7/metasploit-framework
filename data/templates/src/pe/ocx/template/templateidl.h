

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


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


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__


#ifndef __templateidl_h__
#define __templateidl_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef ___Dtemplate_FWD_DEFINED__
#define ___Dtemplate_FWD_DEFINED__
typedef interface _Dtemplate _Dtemplate;

#endif 	/* ___Dtemplate_FWD_DEFINED__ */


#ifndef ___DtemplateEvents_FWD_DEFINED__
#define ___DtemplateEvents_FWD_DEFINED__
typedef interface _DtemplateEvents _DtemplateEvents;

#endif 	/* ___DtemplateEvents_FWD_DEFINED__ */


#ifndef __template_FWD_DEFINED__
#define __template_FWD_DEFINED__

#ifdef __cplusplus
typedef class template template;
#else
typedef struct template template;
#endif /* __cplusplus */

#endif 	/* __template_FWD_DEFINED__ */


#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_template_0000_0000 */
/* [local] */ 

#pragma once
#pragma region Desktop Family
#pragma endregion


extern RPC_IF_HANDLE __MIDL_itf_template_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_template_0000_0000_v0_0_s_ifspec;


#ifndef __templateLib_LIBRARY_DEFINED__
#define __templateLib_LIBRARY_DEFINED__

/* library templateLib */
/* [control][version][uuid] */ 


EXTERN_C const IID LIBID_templateLib;

#ifndef ___Dtemplate_DISPINTERFACE_DEFINED__
#define ___Dtemplate_DISPINTERFACE_DEFINED__

/* dispinterface _Dtemplate */
/* [uuid] */ 


EXTERN_C const IID DIID__Dtemplate;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("3B0404BF-D58D-46D0-B301-86A1BAD0D9CE")
    _Dtemplate : public IDispatch
    {
    };
    
#else 	/* C style interface */

    typedef struct _DtemplateVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            _Dtemplate * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            _Dtemplate * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            _Dtemplate * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            _Dtemplate * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            _Dtemplate * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            _Dtemplate * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            _Dtemplate * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        END_INTERFACE
    } _DtemplateVtbl;

    interface _Dtemplate
    {
        CONST_VTBL struct _DtemplateVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define _Dtemplate_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define _Dtemplate_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define _Dtemplate_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define _Dtemplate_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define _Dtemplate_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define _Dtemplate_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define _Dtemplate_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */


#endif 	/* ___Dtemplate_DISPINTERFACE_DEFINED__ */


#ifndef ___DtemplateEvents_DISPINTERFACE_DEFINED__
#define ___DtemplateEvents_DISPINTERFACE_DEFINED__

/* dispinterface _DtemplateEvents */
/* [uuid] */ 


EXTERN_C const IID DIID__DtemplateEvents;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("06DAD5F2-4719-4FF1-AA60-4C2E8F6D59D7")
    _DtemplateEvents : public IDispatch
    {
    };
    
#else 	/* C style interface */

    typedef struct _DtemplateEventsVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            _DtemplateEvents * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            _DtemplateEvents * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            _DtemplateEvents * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            _DtemplateEvents * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            _DtemplateEvents * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            _DtemplateEvents * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            _DtemplateEvents * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        END_INTERFACE
    } _DtemplateEventsVtbl;

    interface _DtemplateEvents
    {
        CONST_VTBL struct _DtemplateEventsVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define _DtemplateEvents_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define _DtemplateEvents_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define _DtemplateEvents_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define _DtemplateEvents_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define _DtemplateEvents_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define _DtemplateEvents_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define _DtemplateEvents_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */


#endif 	/* ___DtemplateEvents_DISPINTERFACE_DEFINED__ */


EXTERN_C const CLSID CLSID_template;

#ifdef __cplusplus

class DECLSPEC_UUID("56C04F88-9E36-434B-82A3-D552B81A8CB9")
template;
#endif
#endif /* __templateLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


