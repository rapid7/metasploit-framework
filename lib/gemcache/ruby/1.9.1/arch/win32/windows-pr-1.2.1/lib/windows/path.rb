require 'windows/api'

module Windows
  module Path
    API.auto_namespace = 'Windows::Path'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # These constants are for use by the PathGetCharType() function.

    GCT_INVALID   = 0x0000   # Character is not valid in a path.
    GCT_LFNCHAR   = 0x0001   # Character is valid in a long file name.
    GCT_SHORTCHAR = 0x0002   # Character is valid in a short (8.3) file name.
    GCT_WILD      = 0x0004   # Character is a wildcard character.
    GCT_SEPARATOR = 0x0008   # Character is a path separator.

    URL_UNESCAPE                 = 0x10000000
    URL_ESCAPE_UNSAFE            = 0x20000000
    URL_PLUGGABLE_PROTOCOL       = 0x40000000
    URL_WININET_COMPATIBILITY    = 0x80000000
    URL_DONT_ESCAPE_EXTRA_INFO   = 0x02000000
    URL_DONT_UNESCAPE_EXTRA_INFO = URL_DONT_ESCAPE_EXTRA_INFO
    URL_BROWSER_MODE             = URL_DONT_ESCAPE_EXTRA_INFO
    URL_ESCAPE_SPACES_ONLY       = 0x04000000
    URL_DONT_SIMPLIFY            = 0x08000000
    URL_NO_META                  = URL_DONT_SIMPLIFY
    URL_UNESCAPE_INPLACE         = 0x00100000
    URL_CONVERT_IF_DOSPATH       = 0x00200000
    URL_UNESCAPE_HIGH_ANSI_ONLY  = 0x00400000
    URL_INTERNAL_PATH            = 0x00800000
    URL_FILE_USE_PATHURL         = 0x00010000
    URL_DONT_UNESCAPE            = 0x00020000
    URL_ESCAPE_PERCENT           = 0x00001000
    URL_ESCAPE_SEGMENT_ONLY      = 0x00002000
    URL_PARTFLAG_KEEPSCHEME      = 0x00000001
    URL_APPLY_DEFAULT            = 0x00000001
    URL_APPLY_GUESSSCHEME        = 0x00000002
    URL_APPLY_GUESSFILE          = 0x00000004
    URL_APPLY_FORCEAPPLY         = 0x00000008

    # URLIS enum

    URLIS_URL       = 1
    URLIS_OPAQUE    = 2
    URLIS_NOHISTORY = 3
    URLIS_FILEURL   = 4
    URLIS_APPLIABLE = 5
    URLIS_DIRECTORY = 6
    URLIS_HASQUERY  = 7

    API.new('PathAddBackslash', 'P', 'P', 'shlwapi')
    API.new('PathAddExtension', 'PS', 'B', 'shlwapi')
    API.new('PathAppend', 'PS', 'B', 'shlwapi')
    API.new('PathBuildRoot', 'PI', 'P', 'shlwapi')
    API.new('PathCanonicalize', 'PS', 'B', 'shlwapi')
    API.new('PathCombine', 'PSS', 'P', 'shlwapi')
    API.new('PathCommonPrefix', 'SSP', 'I', 'shlwapi')
    API.new('PathCompactPath', 'PPI', 'B', 'shlwapi')
    API.new('PathCompactPathEx', 'PPIL', 'B', 'shlwapi')
    API.new('PathCreateFromUrl', 'SPPL', 'L', 'shlwapi')
    API.new('PathFileExists', 'S', 'B', 'shlwapi')
    API.new('PathFindExtension', 'S', 'P', 'shlwapi')
    API.new('PathFindFileName', 'S', 'P', 'shlwapi')
    API.new('PathFindNextComponent', 'S', 'P', 'shlwapi')
    API.new('PathFindOnPath', 'PS', 'B', 'shlwapi')
    API.new('PathFindSuffixArray', 'SSI', 'P', 'shlwapi')
    API.new('PathGetArgs', 'S', 'P', 'shlwapi')
    API.new('PathGetCharType', 'P', 'I', 'shlwapi')
    API.new('PathGetDriveNumber', 'S', 'I', 'shlwapi')
    API.new('PathIsContentType', 'SS', 'B', 'shlwapi')
    API.new('PathIsDirectory', 'S', 'B', 'shlwapi')
    API.new('PathIsDirectoryEmpty', 'S', 'B', 'shlwapi')
    API.new('PathIsFileSpec', 'S', 'B', 'shlwapi')
    API.new('PathIsLFNFileSpec', 'S', 'B', 'shlwapi')
    API.new('PathIsNetworkPath', 'S', 'B', 'shlwapi')
    API.new('PathIsPrefix', 'SS', 'B', 'shlwapi')
    API.new('PathIsRelative', 'S', 'B', 'shlwapi')
    API.new('PathIsRoot', 'S', 'B', 'shlwapi')
    API.new('PathIsSameRoot', 'SS', 'B', 'shlwapi')
    API.new('PathIsSystemFolder', 'SL', 'B', 'shlwapi')
    API.new('PathIsUNC', 'S', 'B', 'shlwapi')
    API.new('PathIsUNCServer', 'S', 'B', 'shlwapi')
    API.new('PathIsUNCServerShare', 'S', 'B', 'shlwapi')
    API.new('PathIsURL', 'S', 'B', 'shlwapi')
    API.new('PathMakePretty', 'P', 'B', 'shlwapi')
    API.new('PathMakeSystemFolder', 'S', 'B', 'shlwapi')
    API.new('PathMatchSpec', 'SS', 'B', 'shlwapi')
    API.new('PathParseIconLocation', 'P', 'I', 'shlwapi')
    API.new('PathQuoteSpaces', 'P', 'V', 'shlwapi')
    API.new('PathRelativePathTo', 'PPLPL', 'B', 'shlwapi')
    API.new('PathRemoveArgs', 'P', 'V', 'shlwapi')
    API.new('PathRemoveBackslash', 'P', 'P', 'shlwapi')
    API.new('PathRemoveBlanks', 'P', 'V', 'shlwapi')
    API.new('PathRemoveExtension', 'P','V', 'shlwapi')
    API.new('PathRemoveFileSpec', 'P', 'B', 'shlwapi')
    API.new('PathRenameExtension', 'PS', 'B', 'shlwapi')
    API.new('PathSearchAndQualify', 'SPI', 'B', 'shlwapi')
    API.new('PathSetDlgItemPath', 'LIS', 'V', 'shlwapi')
    API.new('PathSkipRoot', 'S', 'P', 'shlwapi')
    API.new('PathStripPath', 'P', 'V', 'shlwapi')
    API.new('PathStripToRoot', 'P', 'B', 'shlwapi')
    API.new('PathUndecorate', 'P', 'V', 'shlwapi')
    API.new('PathUnExpandEnvStrings', 'SPI', 'B', 'shlwapi')
    API.new('PathUnmakeSystemFolder', 'S', 'B', 'shlwapi')
    API.new('PathUnquoteSpaces', 'P', 'V', 'shlwapi')

    API.new('UrlApplyScheme', 'SPPL', 'L', 'shlwapi')
    API.new('UrlCanonicalize', 'SPPL', 'L', 'shlwapi')
    API.new('UrlCombine', 'SSPPL', 'L', 'shlwapi')
    API.new('UrlCompare', 'SSI', 'I', 'shlwapi')
    API.new('UrlCreateFromPath', 'SPPL', 'L', 'shlwapi')
    API.new('UrlEscape', 'SPPL', 'L', 'shlwapi')
    API.new('UrlGetLocation', 'S', 'P', 'shlwapi')
    API.new('UrlGetPart', 'SPPLL', 'L', 'shlwapi')
    API.new('UrlHash', 'SPL', 'L', 'shlwapi')
    API.new('UrlIs', 'SL', 'B', 'shlwapi')
    API.new('UrlIsNoHistory', 'S', 'B', 'shlwapi')
    API.new('UrlIsOpaque', 'S', 'B', 'shlwapi')
    API.new('UrlUnescape', 'PPPL', 'L', 'shlwapi')

    # Macros

    def UrlEscapeSpaces(pszUrl, pszEscaped, pcchEscaped)
      UrlCanonicalize.call(
        pszUrl,
        pszEscaped,
        pcchEscaped,
        URL_ESCAPE_SPACES_ONLY | URL_DONT_ESCAPE_EXTRA_INFO
      )
    end

    def UrlIsFileUrl(pszUrl)
      UrlIsA.call(pszUrl, URLIS_FILEURL)
    end

    def UrlUnescapeInPlace(pszUrl, dwFlags)
      UrlUnescape.call(pszUrl, nil, nil, dwFlags | URL_UNESCAPE_INPLACE)
    end
  end
end
