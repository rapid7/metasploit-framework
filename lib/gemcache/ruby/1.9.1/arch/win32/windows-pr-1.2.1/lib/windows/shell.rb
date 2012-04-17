require 'windows/api'

module Windows
  module Shell
    API.auto_namespace = 'Windows::Shell'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # CSIDL constants
    CSIDL_DESKTOP                 = 0x0000
    CSIDL_INTERNET                = 0x0001
    CSIDL_PROGRAMS                = 0x0002
    CSIDL_CONTROLS                = 0x0003
    CSIDL_PRINTERS                = 0x0004
    CSIDL_PERSONAL                = 0x0005
    CSIDL_FAVORITES               = 0x0006
    CSIDL_STARTUP                 = 0x0007
    CSIDL_RECENT                  = 0x0008
    CSIDL_SENDTO                  = 0x0009
    CSIDL_BITBUCKET               = 0x000a
    CSIDL_STARTMENU               = 0x000b
    CSIDL_MYDOCUMENTS             = 0x000c
    CSIDL_MYMUSIC                 = 0x000d
    CSIDL_MYVIDEO                 = 0x000e
    CSIDL_DESKTOPDIRECTORY        = 0x0010
    CSIDL_DRIVES                  = 0x0011
    CSIDL_NETWORK                 = 0x0012
    CSIDL_NETHOOD                 = 0x0013
    CSIDL_FONTS                   = 0x0014
    CSIDL_TEMPLATES               = 0x0015
    CSIDL_COMMON_STARTMENU        = 0x0016
    CSIDL_COMMON_PROGRAMS         = 0X0017
    CSIDL_COMMON_STARTUP          = 0x0018
    CSIDL_COMMON_FAVORITES        = 0x001f
    CSIDL_COMMON_DESKTOPDIRECTORY = 0x0019
    CSIDL_APPDATA                 = 0x001a
    CSIDL_PRINTHOOD               = 0x001b
    CSIDL_LOCAL_APPDATA           = 0x001c
    CSIDL_ALTSTARTUP              = 0x001d
    CSIDL_COMMON_ALTSTARTUP       = 0x001e
    CSIDL_INTERNET_CACHE          = 0x0020
    CSIDL_COOKIES                 = 0x0021
    CSIDL_HISTORY                 = 0x0022
    CSIDL_COMMON_APPDATA          = 0x0023
    CSIDL_WINDOWS                 = 0x0024
    CSIDL_SYSTEM                  = 0x0025
    CSIDL_PROGRAM_FILES           = 0x0026
    CSIDL_MYPICTURES              = 0x0027
    CSIDL_PROFILE                 = 0x0028
    CSIDL_SYSTEMX86               = 0x0029
    CSIDL_PROGRAM_FILESX86        = 0x002a
    CSIDL_PROGRAM_FILES_COMMON    = 0x002b
    CSIDL_PROGRAM_FILES_COMMONX86 = 0x002c
    CSIDL_COMMON_TEMPLATES        = 0x002d
    CSIDL_COMMON_DOCUMENTS        = 0x002e
    CSIDL_CONNECTIONS             = 0x0031
    CSIDL_COMMON_MUSIC            = 0x0035
    CSIDL_COMMON_PICTURES         = 0x0036
    CSIDL_COMMON_VIDEO            = 0x0037
    CSIDL_RESOURCES               = 0x0038
    CSIDL_RESOURCES_LOCALIZED     = 0x0039
    CSIDL_COMMON_OEM_LINKS        = 0x003a
    CSIDL_CDBURN_AREA             = 0x003b
    CSIDL_COMMON_ADMINTOOLS       = 0x002f
    CSIDL_ADMINTOOLS              = 0x0030
    
    # Return codes
    S_FALSE      = 1
    E_FAIL       = 2147500037
    E_INVALIDARG = 2147483651

    # Flags
    SHGFP_TYPE_CURRENT = 0
    SHGFP_TYPE_DEFAULT = 1

    # Shell file operations
    FO_MOVE   = 0x0001
    FO_COPY   = 0x0002
    FO_DELETE = 0x0003
    FO_RENAME = 0x0004

    FOF_MULTIDESTFILES        = 0x0001
    FOF_CONFIRMMOUSE          = 0x0002
    FOF_SILENT                = 0x0004  # Don't create progress/report
    FOF_RENAMEONCOLLISION     = 0x0008
    FOF_NOCONFIRMATION        = 0x0010  # Don't prompt the user.
    FOF_WANTMAPPINGHANDLE     = 0x0020  # Fill in SHFILEOPSTRUCT.hNameMappings
    FOF_ALLOWUNDO             = 0x0040
    FOF_FILESONLY             = 0x0080  # On *.*, do only files
    FOF_SIMPLEPROGRESS        = 0x0100  # Means don't show names of files
    FOF_NOCONFIRMMKDIR        = 0x0200  # Don't confirm making any needed dirs
    FOF_NOERRORUI             = 0x0400  # Don't put up error UI
    FOF_NOCOPYSECURITYATTRIBS = 0x0800  # Don't copy NT file Sec. Attributes
    FOF_NORECURSION           = 0x1000  # Don't recurse into directories.
    FOF_NO_CONNECTED_ELEMENTS = 0x2000  # Don't operate on connected elements
    FOF_WANTNUKEWARNING       = 0x4000  # During delete op, warn if nuking
    FOF_NORECURSEREPARSE      = 0x8000  # Treat reparse points as objects

    # Shell execute error codes
    SE_ERR_FNF             = 2  # file not found
    SE_ERR_PNF             = 3  # path not found
    SE_ERR_ACCESSDENIED    = 5  # access denied
    SE_ERR_OOM             = 8  # out of memory
    SE_ERR_DLLNOTFOUND     = 32
    SE_ERR_SHARE           = 26
    SE_ERR_ASSOCINCOMPLETE = 27
    SE_ERR_DDETIMEOUT      = 28
    SE_ERR_DDEFAIL         = 29
    SE_ERR_DDEBUSY         = 30
    SE_ERR_NOASSOC         = 31

    # Shell link constants
    SHGNLI_PIDL       = 0x000000001 # pszLinkTo is a pidl
    SHGNLI_PREFIXNAME = 0x000000002 # Make name "Shortcut to xxx"
    SHGNLI_NOUNIQUE   = 0x000000004 # don't do the unique name generation
    SHGNLI_NOLNK      = 0x000000008 # don't add ".lnk" extension

    # File information constants
    SHGFI_ICON              = 0x000000100 # get icon
    SHGFI_DISPLAYNAME       = 0x000000200 # get display name
    SHGFI_TYPENAME          = 0x000000400 # get type name
    SHGFI_ATTRIBUTES        = 0x000000800 # get attributes
    SHGFI_ICONLOCATION      = 0x000001000 # get icon location
    SHGFI_EXETYPE           = 0x000002000 # return exe type
    SHGFI_SYSICONINDEX      = 0x000004000 # get system icon index
    SHGFI_LINKOVERLAY       = 0x000008000 # put a link overlay on icon
    SHGFI_SELECTED          = 0x000010000 # show icon in selected state
    SHGFI_ATTR_SPECIFIED    = 0x000020000 # get only specified attributes
    SHGFI_LARGEICON         = 0x000000000 # get large icon
    SHGFI_SMALLICON         = 0x000000001 # get small icon
    SHGFI_OPENICON          = 0x000000002 # get open icon
    SHGFI_SHELLICONSIZE     = 0x000000004 # get shell size icon
    SHGFI_PIDL              = 0x000000008 # pszPath is a pidl
    SHGFI_USEFILEATTRIBUTES = 0x000000010 # use passed dwFileAttribute
    SHGFI_ADDOVERLAYS       = 0x000000020 # apply the appropriate overlays
    SHGFI_OVERLAYINDEX      = 0x000000040 # Get the index of the overlay
    
    API.new('DragQueryFile', 'LLPL', 'I', 'shell32')
    API.new('ExtractIcon', 'LSI', 'L', 'shell32')
    API.new('ExtractIconEx', 'SIPPI', 'I', 'shell32')
    API.new('FindExecutable', 'SSP', 'L', 'shell32')
    API.new('GetAllUsersProfileDirectory', 'PP', 'B', 'userenv')
    API.new('GetDefaultUserProfileDirectory', 'PP', 'B', 'userenv')
    API.new('GetProfilesDirectory', 'PP', 'B', 'userenv')
    API.new('GetUserProfileDirectory', 'LPP', 'B', 'userenv')
    API.new('ShellAbout', 'LSSL', 'I', 'shell32')
    API.new('SHBrowseForFolder', 'P', 'P', 'shell32')
    API.new('SHChangeNotify', 'LILL', 'V', 'shell32')
    API.new('ShellExecute', 'LSSSSI', 'L', 'shell32')
    API.new('ShellExecuteEx', 'P', 'B', 'shell32')
    API.new('SHFileOperation', 'P', 'I', 'shell32')
    API.new('SHGetFileInfo', 'PLPII', 'L', 'shell32')
    API.new('SHGetFolderLocation', 'LILLP', 'L', 'shell32')
    API.new('SHGetFolderPath', 'LLLLP', 'L', 'shell32')
    API.new('SHGetNewLinkInfo', 'SSPPI', 'B', 'shell32')
    API.new('SHGetPathFromIDList', 'LL', 'B', 'shell32')
    API.new('SHGetSpecialFolderLocation', 'LIP', 'L', 'shell32')
    API.new('SHGetSpecialFolderPath', 'LPLL','L', 'shell32')

    begin
      API.new('SHGetKnownFolderPath', 'LLLP', 'L', 'shell32')
      API.new('SHGetKnownFolderIDList', 'LLLP', 'L', 'shell32')
      API.new('SHGetNameFromIDList', 'PLP', 'L', 'shell32')
    rescue Win32::API::LoadLibraryError
      # Windows Vista or later
    end
  end
end
