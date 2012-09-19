require 'windows/api'

module Windows
  module COM
    API.auto_namespace = 'Windows::COM'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = false

    private

    # These constants are from wtypes.h but are only used in a COM context
    # as far as I know.

    VT_EMPTY    = 0
    VT_NULL     = 1
    VT_I2       = 2
    VT_I4       = 3
    VT_R4       = 4
    VT_R8       = 5
    VT_CY       = 6
    VT_DATE     = 7
    VT_BSTR     = 8
    VT_DISPATCH = 9
    VT_ERROR    = 10
    VT_BOOL     = 11
    VT_VARIANT  = 12
    VT_UNKNOWN  = 13
    VT_DECIMAL  = 14
    VT_I1       = 16
    VT_UI1      = 17
    VT_UI2      = 18
    VT_UI4      = 19
    VT_I8       = 20
    VT_UI8      = 21
    VT_INT      = 22
    VT_UINT     = 23
    VT_VOID     = 24
    VT_HRESULT  = 25
    VT_PTR      = 26

    VT_SAFEARRAY        = 27
    VT_CARRAY           = 28
    VT_USERDEFINED      = 29
    VT_LPSTR            = 30
    VT_LPWSTR           = 31
    VT_RECORD           = 36
    VT_INT_PTR          = 37
    VT_UINT_PTR         = 38
    VT_FILETIME         = 64
    VT_BLOB             = 65
    VT_STREAM           = 66
    VT_STORAGE          = 67
    VT_STREAMED_OBJECT  = 68
    VT_STORED_OBJECT    = 69
    VT_BLOB_OBJECT      = 70
    VT_CF               = 71
    VT_CLSID            = 72
    VT_VERSIONED_STREAM = 73
    VT_BSTR_BLOB        = 0xfff
    VT_VECTOR           = 0x1000
    VT_ARRAY            = 0x2000
    VT_BYREF            = 0x4000
    VT_RESERVED         = 0x8000
    VT_ILLEGAL          = 0xffff
    VT_ILLEGALMASKED    = 0xfff
    VT_TYPEMASK         = 0xfff

    # These constants are from OAldl.h

    INVOKE_FUNC           = 1
    INVOKE_PROPERTYGET    = 2
    INVOKE_PROPERTYPUT    = 4
    INVOKE_PROPERTYPUTREF = 8

    # CLSCTX enum constants

    CLSCTX_INPROC_SERVER          = 0x1
    CLSCTX_INPROC_HANDLER         = 0x2
    CLSCTX_LOCAL_SERVER           = 0x4
    CLSCTX_INPROC_SERVER16        = 0x8
    CLSCTX_REMOTE_SERVER          = 0x10
    CLSCTX_INPROC_HANDLER16       = 0x20
    CLSCTX_RESERVED1              = 0x40
    CLSCTX_RESERVED2              = 0x80
    CLSCTX_RESERVED3              = 0x100
    CLSCTX_RESERVED4              = 0x200
    CLSCTX_NO_CODE_DOWNLOAD       = 0x400
    CLSCTX_RESERVED5              = 0x800
    CLSCTX_NO_CUSTOM_MARSHAL      = 0x1000
    CLSCTX_ENABLE_CODE_DOWNLOAD   = 0x2000
    CLSCTX_NO_FAILURE_LOG         = 0x4000
    CLSCTX_DISABLE_AAA            = 0x8000
    CLSCTX_ENABLE_AAA             = 0x10000
    CLSCTX_FROM_DEFAULT_CONTEXT   = 0x20000
    CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000
    CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000

    # IDispatch

    DISPID_UNKNOWN     = -1
    DISPID_VALUE       = 0
    DISPID_PROPERTYPUT = -3
    DISPID_NEWENUM     = -4
    DISPID_EVALUATE    = -5
    DISPID_CONSTRUCTOR = -6
    DISPID_DESTRUCTOR  = -7
    DISPID_COLLECT     = -8

    # Flags for IDispatch::Invoke

    DISPATCH_METHOD         = 0x1
    DISPATCH_PROPERTYGET    = 0x2
    DISPATCH_PROPERTYPUT    = 0x4
    DISPATCH_PROPERTYPUTREF = 0x8

    API.new('BindMoniker', 'PLPP', 'L', 'ole32')
    API.new('CLSIDFromProgID', 'PP', 'L', 'ole32')
    API.new('CLSIDFromProgIDEx', 'PP', 'L', 'ole32')
    API.new('CLSIDFromString', 'PP', 'L', 'ole32')
    API.new('CoAddRefServerProcess', 'V', 'L', 'ole32')
    API.new('CoAllowSetForegroundWindow', 'PP', 'L', 'ole32')
    API.new('CoCancelCall', 'LL', 'L', 'ole32')
    API.new('CoCopyProxy', 'PP', 'L', 'ole32')
    API.new('CoCreateFreeThreadedMarshaler', 'PP', 'L', 'ole32')
    API.new('CoCreateGuid', 'P', 'L', 'ole32')
    API.new('CoCreateInstance', 'PPLPP', 'L', 'ole32')
    API.new('CoCreateInstanceEx', 'PPLPLP', 'L', 'ole32')
    API.new('CoDisableCallCancellation', 'L', 'L', 'ole32')
    API.new('CoDisconnectObject', 'PL', 'L', 'ole32')
    #API.new('CoDosDateTimeToFileTime', 'LLP', 'L')
    API.new('CoEnableCallCancellation', 'L', 'L', 'ole32')
    API.new('CoFileTimeNow', 'P', 'L', 'ole32')
    API.new('CoFileTimeToDosDateTime', 'LLL', 'B', 'ole32')
    API.new('CoFreeAllLibraries', 'V', 'V', 'ole32')
    API.new('CoFreeLibrary', 'L', 'V', 'ole32')
    API.new('CoFreeUnusedLibraries', 'V', 'V', 'ole32')
    API.new('CoFreeUnusedLibrariesEx', 'V', 'V', 'ole32')
    API.new('CoGetCallContext', 'PP', 'L', 'ole32')
    API.new('CoGetCallerTID', 'P', 'L', 'ole32')
    API.new('CoGetCancelObject', 'LPP', 'L', 'ole32')
    API.new('CoGetClassObject', 'PLPPP', 'L', 'ole32')
    API.new('CoGetContextToken', 'P', 'L', 'ole32')
    API.new('CoGetCurrentLogicalThreadId', 'P', 'L', 'ole32')
    API.new('CoGetCurrentProcess', 'V', 'L', 'ole32')
    API.new('CoGetInstanceFromFile', 'PPPLLPLP', 'L', 'ole32')
    API.new('CoGetInstanceFromIStorage', 'PPPLPLP', 'L', 'ole32')
    API.new('CoInitialize', 'P', 'L', 'ole32')
    API.new('CoTaskMemFree', 'P', 'V', 'ole32')
    API.new('CoUninitialize', 'V', 'V', 'ole32')
    API.new('CoUnmarshalHresult', 'PP', 'L', 'ole32')
    API.new('CoUnmarshalInterface', 'PPP', 'L', 'ole32')
    API.new('CoWaitForMultipleHandles', 'LLLPP', 'L', 'ole32')
    API.new('CreateAntiMoniker', 'P', 'L', 'ole32')
    API.new('CreateAsyncBindCtx', 'LKKP', 'L', 'urlmon')
    API.new('CreateBindCtx', 'LP', 'L', 'ole32')
    API.new('CreateClassMoniker', 'PP', 'L', 'ole32')
    API.new('CreateFileMoniker', 'PP', 'L', 'ole32')
    API.new('CreateGenericComposite', 'PPP', 'L', 'ole32')
    API.new('CreateItemMoniker', 'PPP', 'L', 'ole32')
    API.new('CreateObjrefMoniker', 'PP', 'L', 'ole32')
    API.new('CreatePointerMoniker', 'PP', 'L', 'ole32')
    API.new('GetClassFile', 'PP', 'L', 'ole32')
    API.new('GetRunningObjectTable', 'LP', 'L', 'ole32')
    API.new('IIDFromString', 'PP', 'L', 'ole32')
    API.new('IsAccelerator', 'LIPP', 'B', 'ole32')
    API.new('IsEqualGUID', 'PP', 'B', 'ole32')
    API.new('MkParseDisplayName', 'PPPP', 'L', 'ole32')
    API.new('MonikerCommonPrefixWith', 'PPP', 'L', 'ole32')
    API.new('MonikerRelativePathTo', 'PPPI', 'L', 'ole32')
    API.new('OleDoAutoConvert', 'PP', 'L', 'ole32')
    API.new('OleGetAutoConvert', 'PP', 'L', 'ole32')
    API.new('OleGetIconOfClass', 'PPI', 'L', 'ole32')
    API.new('OleGetIconOfFile', 'PI', 'L', 'ole32')
    API.new('OleIconToCursor', 'PL', 'L', 'olepro32')
    API.new('OleInitialize', 'V', 'L', 'ole32')
    API.new('OleRegGetMiscStatus', 'PLP', 'L', 'ole32')
    API.new('OleRegGetUserType', 'PLP', 'L', 'ole32')
    API.new('OleSetAutoConvert', 'PP', 'L', 'ole32')
    API.new('OleUninitialize', 'V', 'V', 'ole32')
    API.new('ProgIDFromCLSID', 'PP', 'L', 'ole32')
    API.new('StringFromCLSID', 'PP', 'L', 'ole32')
    API.new('StringFromGUID2', 'PPI', 'I', 'ole32')
    API.new('StringFromIID', 'PP', 'L', 'ole32')

    begin
      API.new('CoDisconnectContext', 'L', 'L', 'ole32')
    rescue Win32::API::LoadLibraryError
      # Windows Vista
    end
  end
end
