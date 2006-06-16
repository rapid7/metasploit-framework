/*
 * This file is part of the Metasploit Exploit Framework
 * and is subject to the same licenses and copyrights as
 * the rest of this package.
 */
#ifndef _CPASSIVEX_H
#define _CPASSIVEX_H

#include <windows.h>
#include <atlbase.h>

extern CComModule _Module;

#include <atlcom.h>
#include <ocidl.h>

#include "HttpTunnel.h"

class ATL_NO_VTABLE CPassiveX : 
	public CComObjectRootEx<CComMultiThreadModel>,
	public CComCoClass<CPassiveX, &CLSID_PassiveX>,
	public CComControl<CPassiveX>,
	public IOleObjectImpl<CPassiveX>,
	public IOleControlImpl<CPassiveX>,
	public IOleInPlaceActiveObjectImpl<CPassiveX>,
	public IOleInPlaceObjectWindowlessImpl<CPassiveX>,
	public IObjectWithSiteImpl<CPassiveX>,
	public IProvideClassInfo2Impl<&CLSID_PassiveX, &DIID_PassiveXEvents, &LIBID_PassiveXCOM>,
	public IConnectionPointContainerImpl<CPassiveX>,
	public IDispatchImpl<IPassiveX, &IID_IPassiveX, &LIBID_PassiveXCOM>,
	public IConnectionPointImpl<CPassiveX, &DIID_PassiveXEvents, CComDynamicUnkArray>,
	public IPersistPropertyBagImpl<CPassiveX>,
	public ISupportErrorInfo
{ public:
		CPassiveX();
		~CPassiveX();

		DECLARE_REGISTRY_RESOURCEID(IDR_PASSIVEX)
		DECLARE_PROTECT_FINAL_CONSTRUCT()
		BEGIN_COM_MAP(CPassiveX)
			COM_INTERFACE_ENTRY(IPassiveX)
			COM_INTERFACE_ENTRY(IDispatch)
			COM_INTERFACE_ENTRY(ISupportErrorInfo)
			COM_INTERFACE_ENTRY(IProvideClassInfo)
			COM_INTERFACE_ENTRY(IProvideClassInfo2)
			COM_INTERFACE_ENTRY(IObjectWithSite)
			COM_INTERFACE_ENTRY(IOleInPlaceObjectWindowless)
			COM_INTERFACE_ENTRY(IOleInPlaceObject)
			COM_INTERFACE_ENTRY2(IOleWindow, IOleInPlaceObject)
			COM_INTERFACE_ENTRY(IOleInPlaceActiveObject)
			COM_INTERFACE_ENTRY(IOleControl)
			COM_INTERFACE_ENTRY(IOleObject)
			COM_INTERFACE_ENTRY(IPersistPropertyBag)
			COM_INTERFACE_ENTRY(IConnectionPointContainer)
			COM_INTERFACE_ENTRY_IMPL(IConnectionPointContainer)
		END_COM_MAP()

		// We are a singleton
		DECLARE_CLASSFACTORY_SINGLETON(CPassiveX);

		// Messages
		BEGIN_MSG_MAP(CPassiveX)
			CHAIN_MSG_MAP(CComControl<CPassiveX>)
			DEFAULT_REFLECTION_HANDLER()
		END_MSG_MAP()

		// Connections
		BEGIN_CONNECTION_POINT_MAP(CPassiveX)
			CONNECTION_POINT_ENTRY(DIID_PassiveXEvents)
		END_CONNECTION_POINT_MAP()

		// Properties
		BEGIN_PROPERTY_MAP(CPassiveX)
			PROP_ENTRY("HttpHost", PASSIVEX_PROPERTY_HTTP_HOST, CLSID_NULL)
			PROP_ENTRY("HttpPort", PASSIVEX_PROPERTY_HTTP_PORT, CLSID_NULL)
			PROP_ENTRY("HttpSid", PASSIVEX_PROPERTY_HTTP_SID, CLSID_NULL)
			PROP_ENTRY("HttpUriBase", PASSIVEX_PROPERTY_HTTP_URI_BASE, CLSID_NULL)
			PROP_ENTRY("DownloadSecondStage", PASSIVEX_PROPERTY_DOWNLOAD_SECOND_STAGE, CLSID_NULL)
		END_PROPERTY_MAP()

		// ISupportErrorInfo
		STDMETHOD(InterfaceSupportsErrorInfo)(REFIID riid);

		// IPassiveX
		STDMETHOD(get_HttpHost)(BSTR *Host);
		STDMETHOD(put_HttpHost)(BSTR Host);
		STDMETHOD(get_HttpSid)(BSTR *Sid);
		STDMETHOD(put_HttpSid)(BSTR Sid);
		STDMETHOD(get_HttpUriBase)(BSTR *UriBase);
		STDMETHOD(put_HttpUriBase)(BSTR UriBase);
		STDMETHOD(get_HttpPort)(ULONG *Port);
		STDMETHOD(put_HttpPort)(ULONG Port);
		STDMETHOD(get_DownloadSecondStage)(ULONG *Port);
		STDMETHOD(put_DownloadSecondStage)(ULONG Port);

#ifdef PXDEBUG
		// Debug logging
		static VOID Log(LPCTSTR fmt, ...);
#else
		static VOID Log(LPCTSTR fmt, ...) { }
#endif
	protected:

		VOID Initialize();

		VOID ResetExplorerZoneRestrictions();

		/**************
		 * Attributes *
		 **************/

		// Properties
		CComBSTR   PropHttpHost;
		CComBSTR   PropHttpSid;
		CComBSTR   PropHttpUriBase;
		ULONG      PropHttpPort;

		// Tunnel
		HttpTunnel Tunnel;
};

#endif
