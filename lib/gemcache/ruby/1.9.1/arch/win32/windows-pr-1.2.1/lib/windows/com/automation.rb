require 'windows/api'

module Windows
  module COM
    module Automation
      API.auto_namespace = 'Windows::COM::Automation'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = false

      private
         
      REGKIND_DEFAULT  = 0
      REGKIND_REGISTER = 1
      REGKIND_NONE     = 2
       
      # VARKIND enum
       
      VAR_PERINSTANCE = 0
      VAR_STATIC      = 1
      VAR_CONST       = 2
      VAR_DISPATCH    = 3
       
      # TYPEKIND enum
       
      TKIND_ENUM      = 0
      TKIND_RECORD    = 1
      TKIND_MODULE    = 2
      TKIND_INTERFACE = 3
      TKIND_DISPATCH  = 4
      TKIND_COCLASS   = 5
      TKIND_ALIAS     = 6
      TKIND_UNION     = 7
      TKIND_MAX       = 8
       
      # LIBFLAGS enum
       
      LIBFLAG_FRESTRICTED   = 0x1
      LIBFLAG_FCONTROL      = 0x2
      LIBFLAG_FHIDDEN       = 0x4
      LIBFLAG_FHASDISKIMAGE = 0x8
 
      PARAMFLAG_NONE         =  0     
      PARAMFLAG_FIN          =  0x1     
      PARAMFLAG_FOUT         =  0x2     
      PARAMFLAG_FLCID        =  0x4     
      PARAMFLAG_FRETVAL      =  0x8     
      PARAMFLAG_FOPT         =  0x10     
      PARAMFLAG_FHASDEFAULT  =  0x20     
      PARAMFLAG_FHASCUSTDATA =  0x40
       
      # FUNCFLAGS enum
       
      FUNCFLAG_FRESTRICTED       = 0x1
      FUNCFLAG_FSOURCE           = 0x2
      FUNCFLAG_FBINDABLE         = 0x4
      FUNCFLAG_FREQUESTEDIT      = 0x8
      FUNCFLAG_FDISPLAYBIND      = 0x10
      FUNCFLAG_FDEFAULTBIND      = 0x20
      FUNCFLAG_FHIDDEN           = 0x40
      FUNCFLAG_FUSESGETLASTERROR = 0x80
      FUNCFLAG_FDEFAULTCOLLELEM  = 0x100
      FUNCFLAG_FUIDEFAULT        = 0x200
      FUNCFLAG_FNONBROWSABLE     = 0x400
      FUNCFLAG_FREPLACEABLE      = 0x800
      FUNCFLAG_FIMMEDIATEBIND    = 0x1000
       
      # TYPEFLAGS enum
       
      TYPEFLAG_FAPPOBJECT     = 0x1
      TYPEFLAG_FCANCREATE     = 0x2
      TYPEFLAG_FLICENSED      = 0x4
      TYPEFLAG_FPREDECLID     = 0x8
      TYPEFLAG_FHIDDEN        = 0x10
      TYPEFLAG_FCONTROL       = 0x20
      TYPEFLAG_FDUAL          = 0x40
      TYPEFLAG_FNONEXTENSIBLE = 0x80
      TYPEFLAG_FOLEAUTOMATION = 0x100
      TYPEFLAG_FRESTRICTED    = 0x200
      TYPEFLAG_FAGGREGATABLE  = 0x400
      TYPEFLAG_FREPLACEABLE   = 0x800
      TYPEFLAG_FDISPATCHABLE  = 0x1000
      TYPEFLAG_FREVERSEBIND   = 0x2000
      TYPEFLAG_FPROXY         = 0x4000
       
      # VARFLAGS enum
       
      VARFLAG_FREADONLY        = 0x1
      VARFLAG_FSOURCE          = 0x2
      VARFLAG_FBINDABLE        = 0x4
      VARFLAG_FREQUESTEDIT     = 0x8
      VARFLAG_FDISPLAYBIND     = 0x10
      VARFLAG_FDEFAULTBIND     = 0x20
      VARFLAG_FHIDDEN          = 0x40
      VARFLAG_FRESTRICTED      = 0x80
      VARFLAG_FDEFAULTCOLLELEM = 0x100
      VARFLAG_FUIDEFAULT       = 0x200
      VARFLAG_FNONBROWSABLE    = 0x400
      VARFLAG_FREPLACEABLE     = 0x800
      VARFLAG_FIMMEDIATEBIND   = 0x1000

      API.new('BstrFromVector', 'PP', 'L', 'oleaut32')
      API.new('CreateErrorInfo', 'P', 'L', 'oleaut32')
      API.new('CreateTypeLib2', 'PPP', 'L', 'oleaut32')
      API.new('DispGetIDsOfNames', 'PPLP', 'L', 'oleaut32')
      API.new('DispGetParam', 'PLLPP', 'L', 'oleaut32')
      API.new('DispInvoke', 'PPPLPPPP', 'L', 'oleaut32')
      API.new('GetActiveObject', 'PPP', 'L', 'oleaut32')
      API.new('LoadRegTypeLib', 'PLLLP', 'L', 'oleaut32')
      API.new('LoadTypeLib', 'PP', 'L', 'oleaut32')
      API.new('LoadTypeLibEx', 'PLP', 'L', 'oleaut32')
      API.new('RegisterActiveObject', 'PPLP', 'L', 'oleaut32')
      API.new('RevokeActiveObject', 'LP', 'L', 'oleaut32')       
      API.new('RegisterTypeLib', 'PPP', 'L', 'oleaut32')
      API.new('SafeArrayAccessData', 'PP', 'L', 'oleaut32')
      API.new('SafeArrayAllocData', 'P', 'L', 'oleaut32')
      API.new('SafeArrayAllocDescriptor', 'LP', 'L', 'oleaut32')
      API.new('SafeArrayCopy', 'PP', 'L', 'oleaut32')
      API.new('SafeArrayCopyData', 'PP', 'L', 'oleaut32')
      API.new('SafeArrayCreate', 'LLP', 'L', 'oleaut32')
      API.new('SafeArrayCreateVector', 'LLL', 'L', 'oleaut32')
      API.new('SafeArrayDestroy', 'P', 'L', 'oleaut32')
      API.new('SafeArrayDestroyData', 'P', 'L', 'oleaut32')
      API.new('SafeArrayDestroyDescriptor', 'P', 'L', 'oleaut32')
      API.new('SafeArrayGetDim', 'P', 'L', 'oleaut32')
      API.new('SafeArrayGetElement', 'PLP', 'L', 'oleaut32')
      API.new('SafeArrayGetElemsize', 'P', 'L', 'oleaut32')
      API.new('SafeArrayGetLBound', 'PLP', 'L', 'oleaut32')
      API.new('SafeArrayGetUBound', 'PLP', 'L', 'oleaut32')
      API.new('SafeArrayLock', 'P', 'L', 'oleaut32')
      API.new('SafeArrayPtrOfIndex', 'PPP', 'L', 'oleaut32')
      API.new('SafeArrayPutElement', 'PPP', 'L', 'oleaut32')
      API.new('SafeArrayRedim', 'PP', 'L', 'oleaut32')
      API.new('SafeArrayUnaccessData', 'P', 'L', 'oleaut32')
      API.new('SafeArrayUnlock', 'P', 'L', 'oleaut32')
      API.new('SetErrorInfo', 'LP', 'L', 'oleaut32')
      API.new('SysAllocString', 'P', 'L', 'oleaut32')
      API.new('SysAllocStringByteLen', 'PI', 'L', 'oleaut32')
      API.new('SysFreeString', 'P', 'V', 'oleaut32')
      API.new('SysReAllocString', 'PP', 'L', 'oleaut32')
      API.new('SysReAllocStringLen', 'PPI', 'L', 'oleaut32')
      API.new('SysStringByteLen', 'P', 'L', 'oleaut32')
      API.new('SysStringLen', 'P', 'L', 'oleaut32')
      API.new('SystemTimeToVariantTime', 'PP', 'I', 'oleaut32')
      API.new('UnRegisterTypeLib', 'PLLLL', 'I', 'oleaut32')
      API.new('VectorFromBstr', 'PP', 'L', 'oleaut32')
    end
  end
end
