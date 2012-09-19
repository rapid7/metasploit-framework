require 'windows/api'

module Windows
  module National
    API.auto_namespace = 'Windows::National'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # Code page identifiers.  Used for get_acp_string method. 
    CODE_PAGE = {
      037 => 'IBM EBCDIC = U.S./Canada',
      437 => 'OEM = United States',
      500 => 'IBM EBCDIC - International',  
      708 => 'Arabic - ASMO 708', 
      709 => 'Arabic - ASMO 449+, BCON V4',
      710 => 'Arabic - Transparent Arabic', 
      720 => 'Arabic - Transparent ASMO',
      737 => 'OEM - Greek (formerly 437G)',
      775 => 'OEM - Baltic', 
      850 => 'OEM - Multilingual Latin I',
      852 => 'OEM - Latin II', 
      855 => 'OEM - Cyrillic (primarily Russian)', 
      857 => 'OEM - Turkish', 
      858 => 'OEM - Multilingual Latin I + Euro symbol', 
      860 => 'OEM - Portuguese', 
      861 => 'OEM - Icelandic', 
      862 => 'OEM - Hebrew', 
      863 => 'OEM - Canadian-French', 
      864 => 'OEM - Arabic', 
      865 => 'OEM - Nordic', 
      866 => 'OEM - Russian', 
      869 => 'OEM - Modern Greek', 
      870 => 'IBM EBCDIC - Multilingual/ROECE (Latin-2)', 
      874 => 'ANSI/OEM - Thai (same as 28605, ISO 8859-15)', 
      875 => 'IBM EBCDIC - Modern Greek', 
      932 => 'ANSI/OEM - Japanese, Shift-JIS', 
      936 => 'ANSI/OEM - Simplified Chinese (PRC, Singapore)', 
      949 => 'ANSI/OEM - Korean (Unified Hangul Code)', 
      950 => 'ANSI/OEM - Traditional Chinese (Taiwan; Hong Kong SAR, PRC)',  
      1026 => 'IBM EBCDIC - Turkish (Latin-5)', 
      1047 => 'IBM EBCDIC - Latin 1/Open System', 
      1140 => 'IBM EBCDIC - U.S./Canada (037 + Euro symbol)', 
      1141 => 'IBM EBCDIC - Germany (20273 + Euro symbol)', 
      1142 => 'IBM EBCDIC - Denmark/Norway (20277 + Euro symbol)', 
      1143 => 'IBM EBCDIC - Finland/Sweden (20278 + Euro symbol)', 
      1144 => 'IBM EBCDIC - Italy (20280 + Euro symbol)', 
      1145 => 'IBM EBCDIC - Latin America/Spain (20284 + Euro symbol)', 
      1146 => 'IBM EBCDIC - United Kingdom (20285 + Euro symbol)', 
      1147 => 'IBM EBCDIC - France (20297 + Euro symbol)', 
      1148 => 'IBM EBCDIC - International (500 + Euro symbol)', 
      1149 => 'IBM EBCDIC - Icelandic (20871 + Euro symbol)', 
      1200 => 'Unicode UCS-2 Little-Endian (BMP of ISO 10646)', 
      1201 => 'Unicode UCS-2 Big-Endian', 
      1250 => 'ANSI - Central European',  
      1251 => 'ANSI - Cyrillic', 
      1252 => 'ANSI - Latin I',  
      1253 => 'ANSI - Greek', 
      1254 => 'ANSI - Turkish', 
      1255 => 'ANSI - Hebrew', 
      1256 => 'ANSI - Arabic', 
      1257 => 'ANSI - Baltic', 
      1258 => 'ANSI/OEM - Vietnamese', 
      1361 => 'Korean (Johab)', 
      10000 => 'MAC - Roman', 
      10001 => 'MAC - Japanese', 
      10002 => 'MAC - Traditional Chinese (Big5)', 
      10003 => 'MAC - Korean', 
      10004 => 'MAC - Arabic', 
      10005 => 'MAC - Hebrew', 
      10006 => 'MAC - Greek I', 
      10007 => 'MAC - Cyrillic', 
      10008 => 'MAC - Simplified Chinese (GB 2312)', 
      10010 => 'MAC - Romania', 
      10017 => 'MAC - Ukraine', 
      10021 => 'MAC - Thai', 
      10029 => 'MAC - Latin II', 
      10079 => 'MAC - Icelandic', 
      10081 => 'MAC - Turkish', 
      10082 => 'MAC - Croatia', 
      12000 => 'Unicode UCS-4 Little-Endian', 
      12001 => 'Unicode UCS-4 Big-Endian', 
      20000 => 'CNS - Taiwan',  
      20001 => 'TCA - Taiwan', 
      20002 => 'Eten - Taiwan',  
      20003 => 'IBM5550 - Taiwan',  
      20004 => 'TeleText - Taiwan',  
      20005 => 'Wang - Taiwan',  
      20105 => 'IA5 IRV International Alphabet No. 5 (7-bit)', 
      20106 => 'IA5 German (7-bit)', 
      20107 => 'IA5 Swedish (7-bit)',
      20108 => 'IA5 Norwegian (7-bit)', 
      20127 => 'US-ASCII (7-bit)', 
      20261 => 'T.61',
      20269 => 'ISO 6937 Non-Spacing Accent',
      20273 => 'IBM EBCDIC - Germany', 
      20277 => 'IBM EBCDIC - Denmark/Norway', 
      20278 => 'IBM EBCDIC - Finland/Sweden',
      20280 => 'IBM EBCDIC - Italy', 
      20284 => 'IBM EBCDIC - Latin America/Spain',
      20285 => 'IBM EBCDIC - United Kingdom', 
      20290 => 'IBM EBCDIC - Japanese Katakana Extended', 
      20297 => 'IBM EBCDIC - France', 
      20420 => 'IBM EBCDIC - Arabic', 
      20423 => 'IBM EBCDIC - Greek', 
      20424 => 'IBM EBCDIC - Hebrew', 
      20833 => 'IBM EBCDIC - Korean Extended', 
      20838 => 'IBM EBCDIC - Thai', 
      20866 => 'Russian - KOI8-R', 
      20871 => 'IBM EBCDIC - Icelandic', 
      20880 => 'IBM EBCDIC - Cyrillic (Russian)', 
      20905 => 'IBM EBCDIC - Turkish', 
      20924 => 'IBM EBCDIC - Latin-1/Open System (1047 + Euro symbol)', 
      20932 => 'JIS X 0208-1990 & 0121-1990', 
      20936 => 'Simplified Chinese (GB2312)', 
      21025 => 'IBM EBCDIC - Cyrillic (Serbian, Bulgarian)', 
      21027 => '(deprecated)', 
      21866 => 'Ukrainian (KOI8-U)', 
      28591 => 'ISO 8859-1 Latin I', 
      28592 => 'ISO 8859-2 Central Europe', 
      28593 => 'ISO 8859-3 Latin 3',  
      28594 => 'ISO 8859-4 Baltic', 
      28595 => 'ISO 8859-5 Cyrillic', 
      28596 => 'ISO 8859-6 Arabic', 
      28597 => 'ISO 8859-7 Greek', 
      28598 => 'ISO 8859-8 Hebrew', 
      28599 => 'ISO 8859-9 Latin 5', 
      28605 => 'ISO 8859-15 Latin 9', 
      29001 => 'Europa 3', 
      38598 => 'ISO 8859-8 Hebrew', 
      50220 => 'ISO 2022 Japanese with no halfwidth Katakana', 
      50221 => 'ISO 2022 Japanese with halfwidth Katakana', 
      50222 => 'ISO 2022 Japanese JIS X 0201-1989', 
      50225 => 'ISO 2022 Korean',  
      50227 => 'ISO 2022 Simplified Chinese', 
      50229 => 'ISO 2022 Traditional Chinese', 
      50930 => 'Japanese (Katakana) Extended', 
      50931 => 'US/Canada and Japanese', 
      50933 => 'Korean Extended and Korean', 
      50935 => 'Simplified Chinese Extended and Simplified Chinese', 
      50936 => 'Simplified Chinese', 
      50937 => 'US/Canada and Traditional Chinese', 
      50939 => 'Japanese (Latin) Extended and Japanese', 
      51932 => 'EUC - Japanese', 
      51936 => 'EUC - Simplified Chinese', 
      51949 => 'EUC - Korean', 
      51950 => 'EUC - Traditional Chinese', 
      52936 => 'HZ-GB2312 Simplified Chinese',  
      54936 => 'Windows XP: GB18030 Simplified Chinese (4 Byte)',  
      57002 => 'ISCII Devanagari', 
      57003 => 'ISCII Bengali', 
      57004 => 'ISCII Tamil', 
      57005 => 'ISCII Telugu', 
      57006 => 'ISCII Assamese', 
      57007 => 'ISCII Oriya', 
      57008 => 'ISCII Kannada', 
      57009 => 'ISCII Malayalam', 
      57010 => 'ISCII Gujarati', 
      57011 => 'ISCII Punjabi', 
      65000 => 'Unicode UTF-7', 
      65001 => 'Unicode UTF-8'
    }
      
    LANG_NEUTRAL      = 0x00
    LANG_INVARIANT    = 0x7f

    LANG_AFRIKAANS    = 0x36
    LANG_ALBANIAN     = 0x1c
    LANG_ARABIC       = 0x01
    LANG_ARMENIAN     = 0x2b
    LANG_ASSAMESE     = 0x4d
    LANG_AZERI        = 0x2c
    LANG_BASQUE       = 0x2d
    LANG_BELARUSIAN   = 0x23
    LANG_BENGALI      = 0x45
    LANG_BOSNIAN      = 0x1a
    LANG_BULGARIAN    = 0x02
    LANG_CATALAN      = 0x03
    LANG_CHINESE      = 0x04
    LANG_CROATIAN     = 0x1a
    LANG_CZECH        = 0x05
    LANG_DANISH       = 0x06
    LANG_DIVEHI       = 0x65
    LANG_DUTCH        = 0x13
    LANG_ENGLISH      = 0x09
    LANG_ESTONIAN     = 0x25
    LANG_FAEROESE     = 0x38
    LANG_FARSI        = 0x29
    LANG_FINNISH      = 0x0b
    LANG_FRENCH       = 0x0c
    LANG_GALICIAN     = 0x56
    LANG_GEORGIAN     = 0x37
    LANG_GERMAN       = 0x07
    LANG_GREEK        = 0x08
    LANG_GUJARATI     = 0x47
    LANG_HEBREW       = 0x0d
    LANG_HINDI        = 0x39
    LANG_HUNGARIAN    = 0x0e
    LANG_ICELANDIC    = 0x0f
    LANG_INDONESIAN   = 0x21
    LANG_ITALIAN      = 0x10
    LANG_JAPANESE     = 0x11
    LANG_KANNADA      = 0x4b
    LANG_KASHMIRI     = 0x60
    LANG_KAZAK        = 0x3f
    LANG_KONKANI      = 0x57
    LANG_KOREAN       = 0x12
    LANG_KYRGYZ       = 0x40
    LANG_LATVIAN      = 0x26
    LANG_LITHUANIAN   = 0x27
    LANG_MACEDONIAN   = 0x2f
    LANG_MALAY        = 0x3e
    LANG_MALAYALAM    = 0x4c
    LANG_MALTESE      = 0x3a
    LANG_MANIPURI     = 0x58
    LANG_MAORI        = 0x81
    LANG_MARATHI      = 0x4e
    LANG_MONGOLIAN    = 0x50
    LANG_NEPALI       = 0x61
    LANG_NORWEGIAN    = 0x14
    LANG_ORIYA        = 0x48
    LANG_POLISH       = 0x15
    LANG_PORTUGUESE   = 0x16
    LANG_PUNJABI      = 0x46
    LANG_QUECHUA      = 0x6b
    LANG_ROMANIAN     = 0x18
    LANG_RUSSIAN      = 0x19
    LANG_SAMI         = 0x3b
    LANG_SANSKRIT     = 0x4f
    LANG_SERBIAN      = 0x1a
    LANG_SINDHI       = 0x59
    LANG_SLOVAK       = 0x1b
    LANG_SLOVENIAN    = 0x24
    LANG_SOTHO        = 0x6c
    LANG_SPANISH      = 0x0a
    LANG_SWAHILI      = 0x41
    LANG_SWEDISH      = 0x1d
    LANG_SYRIAC       = 0x5a
    LANG_TAMIL        = 0x49
    LANG_TATAR        = 0x44
    LANG_TELUGU       = 0x4a
    LANG_THAI         = 0x1e
    LANG_TSWANA       = 0x32
    LANG_TURKISH      = 0x1f
    LANG_UKRAINIAN    = 0x22
    LANG_URDU         = 0x20
    LANG_UZBEK        = 0x43
    LANG_VIETNAMESE   = 0x2a
    LANG_WELSH        = 0x52
    LANG_XHOSA        = 0x34
    LANG_ZULU         = 0x35
   
    SUBLANG_NEUTRAL                 = 0x00    # language neutral
    SUBLANG_DEFAULT                 = 0x01    # user default
    SUBLANG_SYS_DEFAULT             = 0x02    # system default

    SUBLANG_ARABIC_SAUDI_ARABIA     = 0x01    # Arabic (Saudi Arabia)
    SUBLANG_ARABIC_IRAQ             = 0x02    # Arabic (Iraq)
    SUBLANG_ARABIC_EGYPT            = 0x03    # Arabic (Egypt)
    SUBLANG_ARABIC_LIBYA            = 0x04    # Arabic (Libya)
    SUBLANG_ARABIC_ALGERIA          = 0x05    # Arabic (Algeria)
    SUBLANG_ARABIC_MOROCCO          = 0x06    # Arabic (Morocco)
    SUBLANG_ARABIC_TUNISIA          = 0x07    # Arabic (Tunisia)
    SUBLANG_ARABIC_OMAN             = 0x08    # Arabic (Oman)
    SUBLANG_ARABIC_YEMEN            = 0x09    # Arabic (Yemen)
    SUBLANG_ARABIC_SYRIA            = 0x0a    # Arabic (Syria)
    SUBLANG_ARABIC_JORDAN           = 0x0b    # Arabic (Jordan)
    SUBLANG_ARABIC_LEBANON          = 0x0c    # Arabic (Lebanon)
    SUBLANG_ARABIC_KUWAIT           = 0x0d    # Arabic (Kuwait)
    SUBLANG_ARABIC_UAE              = 0x0e    # Arabic (U.A.E)
    SUBLANG_ARABIC_BAHRAIN          = 0x0f    # Arabic (Bahrain)
    SUBLANG_ARABIC_QATAR            = 0x10    # Arabic (Qatar)
    SUBLANG_AZERI_LATIN             = 0x01    # Azeri (Latin)
    SUBLANG_AZERI_CYRILLIC          = 0x02    # Azeri (Cyrillic)
    SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN = 0x05 # Bosnian (Bosnia and Herzegovina - Latin)
    SUBLANG_CHINESE_TRADITIONAL     = 0x01    # Chinese (Taiwan)
    SUBLANG_CHINESE_SIMPLIFIED      = 0x02    # Chinese (PR China)
    SUBLANG_CHINESE_HONGKONG        = 0x03    # Chinese (Hong Kong S.A.R., P.R.C.)
    SUBLANG_CHINESE_SINGAPORE       = 0x04    # Chinese (Singapore)
    SUBLANG_CHINESE_MACAU           = 0x05    # Chinese (Macau S.A.R.)
    SUBLANG_CROATIAN_CROATIA        = 0x01    # Croatian (Croatia)
    SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN = 0x04 # Croatian (Bosnia and Herzegovina - Latin)
    SUBLANG_DUTCH                   = 0x01    # Dutch
    SUBLANG_DUTCH_BELGIAN           = 0x02    # Dutch (Belgian)
    SUBLANG_ENGLISH_US              = 0x01    # English (USA)
    SUBLANG_ENGLISH_UK              = 0x02    # English (UK)
    SUBLANG_ENGLISH_AUS             = 0x03    # English (Australian)
    SUBLANG_ENGLISH_CAN             = 0x04    # English (Canadian)
    SUBLANG_ENGLISH_NZ              = 0x05    # English (New Zealand)
    SUBLANG_ENGLISH_EIRE            = 0x06    # English (Irish)
    SUBLANG_ENGLISH_SOUTH_AFRICA    = 0x07    # English (South Africa)
    SUBLANG_ENGLISH_JAMAICA         = 0x08    # English (Jamaica)
    SUBLANG_ENGLISH_CARIBBEAN       = 0x09    # English (Caribbean)
    SUBLANG_ENGLISH_BELIZE          = 0x0a    # English (Belize)
    SUBLANG_ENGLISH_TRINIDAD        = 0x0b    # English (Trinidad)
    SUBLANG_ENGLISH_ZIMBABWE        = 0x0c    # English (Zimbabwe)
    SUBLANG_ENGLISH_PHILIPPINES     = 0x0d    # English (Philippines)
    SUBLANG_FRENCH                  = 0x01    # French
    SUBLANG_FRENCH_BELGIAN          = 0x02    # French (Belgian)
    SUBLANG_FRENCH_CANADIAN         = 0x03    # French (Canadian)
    SUBLANG_FRENCH_SWISS            = 0x04    # French (Swiss)
    SUBLANG_FRENCH_LUXEMBOURG       = 0x05    # French (Luxembourg)
    SUBLANG_FRENCH_MONACO           = 0x06    # French (Monaco)
    SUBLANG_GERMAN                  = 0x01    # German
    SUBLANG_GERMAN_SWISS            = 0x02    # German (Swiss)
    SUBLANG_GERMAN_AUSTRIAN         = 0x03    # German (Austrian)
    SUBLANG_GERMAN_LUXEMBOURG       = 0x04    # German (Luxembourg)
    SUBLANG_GERMAN_LIECHTENSTEIN    = 0x05    # German (Liechtenstein)
    SUBLANG_ITALIAN                 = 0x01    # Italian
    SUBLANG_ITALIAN_SWISS           = 0x02    # Italian (Swiss)
    SUBLANG_KASHMIRI_SASIA          = 0x02    # Kashmiri (South Asia)
    SUBLANG_KASHMIRI_INDIA          = 0x02    # For app compatibility only
    SUBLANG_KOREAN                  = 0x01    # Korean (Extended Wansung)
    SUBLANG_LITHUANIAN              = 0x01    # Lithuanian
    SUBLANG_MALAY_MALAYSIA          = 0x01    # Malay (Malaysia)
    SUBLANG_MALAY_BRUNEI_DARUSSALAM = 0x02    # Malay (Brunei Darussalam)
    SUBLANG_NEPALI_INDIA            = 0x02    # Nepali (India)
    SUBLANG_NORWEGIAN_BOKMAL        = 0x01    # Norwegian (Bokmal)
    SUBLANG_NORWEGIAN_NYNORSK       = 0x02    # Norwegian (Nynorsk)
    SUBLANG_PORTUGUESE              = 0x02    # Portuguese
    SUBLANG_PORTUGUESE_BRAZILIAN    = 0x01    # Portuguese (Brazilian)
    SUBLANG_QUECHUA_BOLIVIA         = 0x01    # Quechua (Bolivia)
    SUBLANG_QUECHUA_ECUADOR         = 0x02    # Quechua (Ecuador)
    SUBLANG_QUECHUA_PERU            = 0x03    # Quechua (Peru)
    SUBLANG_SAMI_NORTHERN_NORWAY    = 0x01    # Northern Sami (Norway)
    SUBLANG_SAMI_NORTHERN_SWEDEN    = 0x02    # Northern Sami (Sweden)
    SUBLANG_SAMI_NORTHERN_FINLAND   = 0x03    # Northern Sami (Finland)
    SUBLANG_SAMI_LULE_NORWAY        = 0x04    # Lule Sami (Norway)
    SUBLANG_SAMI_LULE_SWEDEN        = 0x05    # Lule Sami (Sweden)
    SUBLANG_SAMI_SOUTHERN_NORWAY    = 0x06    # Southern Sami (Norway)
    SUBLANG_SAMI_SOUTHERN_SWEDEN    = 0x07    # Southern Sami (Sweden)
    SUBLANG_SAMI_SKOLT_FINLAND      = 0x08    # Skolt Sami (Finland)
    SUBLANG_SAMI_INARI_FINLAND      = 0x09    # Inari Sami (Finland)
    SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN =   0x06  # Serbian (Bosnia and Herzegovina - Latin)
    SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC = 0x07 # Serbian (Bosnia and Herzegovina - Cyrillic)
    SUBLANG_SERBIAN_LATIN            = 0x02    # Serbian (Latin)
    SUBLANG_SERBIAN_CYRILLIC         = 0x03    # Serbian (Cyrillic)
    SUBLANG_SOTHO_NORTHERN_SOUTH_AFRICA = 0x01 # Northern Sotho (South Africa)
    SUBLANG_SPANISH                 = 0x01     # Spanish (Castilian)
    SUBLANG_SPANISH_MEXICAN         = 0x02     # Spanish (Mexican)
    SUBLANG_SPANISH_MODERN          = 0x03     # Spanish (Modern)
    SUBLANG_SPANISH_GUATEMALA       = 0x04     # Spanish (Guatemala)
    SUBLANG_SPANISH_COSTA_RICA      = 0x05     # Spanish (Costa Rica)
    SUBLANG_SPANISH_PANAMA          = 0x06     # Spanish (Panama)
    SUBLANG_SPANISH_DOMINICAN_REPUBLIC = 0x07  # Spanish (Dominican Republic)
    SUBLANG_SPANISH_VENEZUELA       = 0x08     # Spanish (Venezuela)
    SUBLANG_SPANISH_COLOMBIA        = 0x09     # Spanish (Colombia)
    SUBLANG_SPANISH_PERU            = 0x0a     # Spanish (Peru)
    SUBLANG_SPANISH_ARGENTINA       = 0x0b     # Spanish (Argentina)
    SUBLANG_SPANISH_ECUADOR         = 0x0c     # Spanish (Ecuador)
    SUBLANG_SPANISH_CHILE           = 0x0d     # Spanish (Chile)
    SUBLANG_SPANISH_URUGUAY         = 0x0e     # Spanish (Uruguay)
    SUBLANG_SPANISH_PARAGUAY        = 0x0f     # Spanish (Paraguay)
    SUBLANG_SPANISH_BOLIVIA         = 0x10     # Spanish (Bolivia)
    SUBLANG_SPANISH_EL_SALVADOR     = 0x11     # Spanish (El Salvador)
    SUBLANG_SPANISH_HONDURAS        = 0x12     # Spanish (Honduras)
    SUBLANG_SPANISH_NICARAGUA       = 0x13     # Spanish (Nicaragua)
    SUBLANG_SPANISH_PUERTO_RICO     = 0x14     # Spanish (Puerto Rico)
    SUBLANG_SWEDISH                 = 0x01     # Swedish
    SUBLANG_SWEDISH_FINLAND         = 0x02     # Swedish (Finland)
    SUBLANG_URDU_PAKISTAN           = 0x01     # Urdu (Pakistan)
    SUBLANG_URDU_INDIA              = 0x02     # Urdu (India)
    SUBLANG_UZBEK_LATIN             = 0x01     # Uzbek (Latin)
    SUBLANG_UZBEK_CYRILLIC          = 0x02     # Uzbek (Cyrillic)
    
    LOCALE_NOUSEROVERRIDE         = 0x80000000
    LOCALE_USE_CP_ACP             = 0x40000000
    LOCALE_RETURN_NUMBER          = 0x20000000

    LOCALE_ILANGUAGE              = 0x00000001 # Language ID
    LOCALE_SLANGUAGE              = 0x00000002 # Localized name of language
    LOCALE_SENGLANGUAGE           = 0x00001001 # English name of language
    LOCALE_SABBREVLANGNAME        = 0x00000003 # Abbreviated language name
    LOCALE_SNATIVELANGNAME        = 0x00000004 # Native name of language

    LOCALE_ICOUNTRY               = 0x00000005 # Country code
    LOCALE_SCOUNTRY               = 0x00000006 # Localized name of country
    LOCALE_SENGCOUNTRY            = 0x00001002 # English name of country
    LOCALE_SABBREVCTRYNAME        = 0x00000007 # Abbreviated country name
    LOCALE_SNATIVECTRYNAME        = 0x00000008 # Native name of country

    LOCALE_IDEFAULTLANGUAGE       = 0x00000009 # default language id
    LOCALE_IDEFAULTCOUNTRY        = 0x0000000A # default country code
    LOCALE_IDEFAULTCODEPAGE       = 0x0000000B # default oem code page
    LOCALE_IDEFAULTANSICODEPAGE   = 0x00001004 # default ansi code page
    LOCALE_IDEFAULTMACCODEPAGE    = 0x00001011 # default mac code page

    LOCALE_SLIST                  = 0x0000000C # list item separator
    LOCALE_IMEASURE               = 0x0000000D # 0 = metric, 1 = US

    LOCALE_SDECIMAL               = 0x0000000E # decimal separator
    LOCALE_STHOUSAND              = 0x0000000F # thousand separator
    LOCALE_SGROUPING              = 0x00000010 # digit grouping
    LOCALE_IDIGITS                = 0x00000011 # number of fractional digits
    LOCALE_ILZERO                 = 0x00000012 # leading zeros for decimal
    LOCALE_INEGNUMBER             = 0x00001010 # negative number mode
    LOCALE_SNATIVEDIGITS          = 0x00000013 # native ascii 0-9

    LOCALE_SCURRENCY              = 0x00000014   # local monetary symbol
    LOCALE_SINTLSYMBOL            = 0x00000015   # intl monetary symbol
    LOCALE_SMONDECIMALSEP         = 0x00000016   # monetary decimal separator
    LOCALE_SMONTHOUSANDSEP        = 0x00000017   # monetary thousand separator
    LOCALE_SMONGROUPING           = 0x00000018   # monetary grouping
    LOCALE_ICURRDIGITS            = 0x00000019   # # local monetary digits
    LOCALE_IINTLCURRDIGITS        = 0x0000001A   # # intl monetary digits
    LOCALE_ICURRENCY              = 0x0000001B   # positive currency mode
    LOCALE_INEGCURR               = 0x0000001C   # negative currency mode

    LOCALE_SDATE                  = 0x0000001D   # date separator
    LOCALE_STIME                  = 0x0000001E   # time separator
    LOCALE_SSHORTDATE             = 0x0000001F   # short date format string
    LOCALE_SLONGDATE              = 0x00000020   # long date format string
    LOCALE_STIMEFORMAT            = 0x00001003   # time format string
    LOCALE_IDATE                  = 0x00000021   # short date format ordering
    LOCALE_ILDATE                 = 0x00000022   # long date format ordering
    LOCALE_ITIME                  = 0x00000023   # time format specifier
    LOCALE_ITIMEMARKPOSN          = 0x00001005   # time marker position
    LOCALE_ICENTURY               = 0x00000024   # century format specifier (short date)
    LOCALE_ITLZERO                = 0x00000025   # leading zeros in time field
    LOCALE_IDAYLZERO              = 0x00000026   # leading zeros in day field (short date)
    LOCALE_IMONLZERO              = 0x00000027   # leading zeros in month field (short date)
    LOCALE_S1159                  = 0x00000028   # AM designator
    LOCALE_S2359                  = 0x00000029   # PM designator

    LOCALE_ICALENDARTYPE          = 0x00001009   # type of calendar specifier
    LOCALE_IOPTIONALCALENDAR      = 0x0000100B   # additional calendar types specifier
    LOCALE_IFIRSTDAYOFWEEK        = 0x0000100C   # first day of week specifier
    LOCALE_IFIRSTWEEKOFYEAR       = 0x0000100D   # first week of year specifier

    LOCALE_SDAYNAME1              = 0x0000002A   # long name for Monday
    LOCALE_SDAYNAME2              = 0x0000002B   # long name for Tuesday
    LOCALE_SDAYNAME3              = 0x0000002C   # long name for Wednesday
    LOCALE_SDAYNAME4              = 0x0000002D   # long name for Thursday
    LOCALE_SDAYNAME5              = 0x0000002E   # long name for Friday
    LOCALE_SDAYNAME6              = 0x0000002F   # long name for Saturday
    LOCALE_SDAYNAME7              = 0x00000030   # long name for Sunday
    LOCALE_SABBREVDAYNAME1        = 0x00000031   # abbreviated name for Monday
    LOCALE_SABBREVDAYNAME2        = 0x00000032   # abbreviated name for Tuesday
    LOCALE_SABBREVDAYNAME3        = 0x00000033   # abbreviated name for Wednesday
    LOCALE_SABBREVDAYNAME4        = 0x00000034   # abbreviated name for Thursday
    LOCALE_SABBREVDAYNAME5        = 0x00000035   # abbreviated name for Friday
    LOCALE_SABBREVDAYNAME6        = 0x00000036   # abbreviated name for Saturday
    LOCALE_SABBREVDAYNAME7        = 0x00000037   # abbreviated name for Sunday
    LOCALE_SMONTHNAME1            = 0x00000038   # long name for January
    LOCALE_SMONTHNAME2            = 0x00000039   # long name for February
    LOCALE_SMONTHNAME3            = 0x0000003A   # long name for March
    LOCALE_SMONTHNAME4            = 0x0000003B   # long name for April
    LOCALE_SMONTHNAME5            = 0x0000003C   # long name for May
    LOCALE_SMONTHNAME6            = 0x0000003D   # long name for June
    LOCALE_SMONTHNAME7            = 0x0000003E   # long name for July
    LOCALE_SMONTHNAME8            = 0x0000003F   # long name for August
    LOCALE_SMONTHNAME9            = 0x00000040   # long name for September
    LOCALE_SMONTHNAME10           = 0x00000041   # long name for October
    LOCALE_SMONTHNAME11           = 0x00000042   # long name for November
    LOCALE_SMONTHNAME12           = 0x00000043   # long name for December
    LOCALE_SMONTHNAME13           = 0x0000100E   # long name for 13th month (if exists)
    LOCALE_SABBREVMONTHNAME1      = 0x00000044   # abbreviated name for January
    LOCALE_SABBREVMONTHNAME2      = 0x00000045   # abbreviated name for February
    LOCALE_SABBREVMONTHNAME3      = 0x00000046   # abbreviated name for March
    LOCALE_SABBREVMONTHNAME4      = 0x00000047   # abbreviated name for April
    LOCALE_SABBREVMONTHNAME5      = 0x00000048   # abbreviated name for May
    LOCALE_SABBREVMONTHNAME6      = 0x00000049   # abbreviated name for June
    LOCALE_SABBREVMONTHNAME7      = 0x0000004A   # abbreviated name for July
    LOCALE_SABBREVMONTHNAME8      = 0x0000004B   # abbreviated name for August
    LOCALE_SABBREVMONTHNAME9      = 0x0000004C   # abbreviated name for September
    LOCALE_SABBREVMONTHNAME10     = 0x0000004D   # abbreviated name for October
    LOCALE_SABBREVMONTHNAME11     = 0x0000004E   # abbreviated name for November
    LOCALE_SABBREVMONTHNAME12     = 0x0000004F   # abbreviated name for December
    LOCALE_SABBREVMONTHNAME13     = 0x0000100F   # abbreviated name for 13th month (if exists)

    LOCALE_SPOSITIVESIGN          = 0x00000050   # positive sign
    LOCALE_SNEGATIVESIGN          = 0x00000051   # negative sign
    LOCALE_IPOSSIGNPOSN           = 0x00000052   # positive sign position
    LOCALE_INEGSIGNPOSN           = 0x00000053   # negative sign position
    LOCALE_IPOSSYMPRECEDES        = 0x00000054   # mon sym precedes pos amt
    LOCALE_IPOSSEPBYSPACE         = 0x00000055   # mon sym sep by space from pos amt
    LOCALE_INEGSYMPRECEDES        = 0x00000056   # mon sym precedes neg amt
    LOCALE_INEGSEPBYSPACE         = 0x00000057   # mon sym sep by space from neg amt

    LOCALE_FONTSIGNATURE          = 0x00000058   # font signature
    LOCALE_SISO639LANGNAME        = 0x00000059   # ISO abbreviated language name
    LOCALE_SISO3166CTRYNAME       = 0x0000005A   # ISO abbreviated country name

    LOCALE_IDEFAULTEBCDICCODEPAGE = 0x00001012   # default ebcdic code page
    LOCALE_IPAPERSIZE             = 0x0000100A   # 1 = letter, 5 = legal, 8 = a3, 9 = a4
    LOCALE_SENGCURRNAME           = 0x00001007   # english name of currency
    LOCALE_SNATIVECURRNAME        = 0x00001008   # native name of currency
    LOCALE_SYEARMONTH             = 0x00001006   # year month format string
    LOCALE_SSORTNAME              = 0x00001013   # sort name
    LOCALE_IDIGITSUBSTITUTION     = 0x00001014   # 0 = context, 1 = none, 2 = national

    TIME_NOMINUTESORSECONDS   = 0x00000001  # do not use minutes or seconds
    TIME_NOSECONDS            = 0x00000002  # do not use seconds
    TIME_NOTIMEMARKER         = 0x00000004  # do not use time marker
    TIME_FORCE24HOURFORMAT    = 0x00000008  # always use 24 hour format

    DATE_SHORTDATE            = 0x00000001  # use short date picture
    DATE_LONGDATE             = 0x00000002  # use long date picture
    DATE_USE_ALT_CALENDAR     = 0x00000004  # use alternate calendar (if any)

    DATE_YEARMONTH            = 0x00000008  # use year month picture
    DATE_LTRREADING           = 0x00000010  # add marks for left to right reading order layout
    DATE_RTLREADING           = 0x00000020  # add marks for right to left reading order layout

    SORT_DEFAULT                    = 0x0     # sorting default

    SORT_JAPANESE_XJIS              = 0x0     # Japanese XJIS order
    SORT_JAPANESE_UNICODE           = 0x1     # Japanese Unicode order

    SORT_CHINESE_BIG5               = 0x0     # Chinese BIG5 order
    SORT_CHINESE_PRCP               = 0x0     # PRC Chinese Phonetic order
    SORT_CHINESE_UNICODE            = 0x1     # Chinese Unicode order
    SORT_CHINESE_PRC                = 0x2     # PRC Chinese Stroke Count order
    SORT_CHINESE_BOPOMOFO           = 0x3     # Traditional Chinese Bopomofo order
 
    SORT_KOREAN_KSC                 = 0x0     # Korean KSC order
    SORT_KOREAN_UNICODE             = 0x1     # Korean Unicode order

    SORT_GERMAN_PHONE_BOOK          = 0x1     # German Phone Book order

    SORT_HUNGARIAN_DEFAULT          = 0x0     # Hungarian Default order
    SORT_HUNGARIAN_TECHNICAL        = 0x1     # Hungarian Technical order

    SORT_GEORGIAN_TRADITIONAL       = 0x0     # Georgian Traditional order
    SORT_GEORGIAN_MODERN            = 0x1     # Georgian Modern order

    LANG_SYSTEM_DEFAULT   = 2048
    LANG_USER_DEFAULT     = 1024
    LOCALE_SYSTEM_DEFAULT = 2048
    LOCALE_USER_DEFAULT   = 1024
    LOCALE_INVARIANT      = 8323072
    
    API.new('CompareString', 'LLPIPI', 'I')
    API.new('EnumDateFormats', 'KLL', 'B')
    API.new('EnumDateFormatsEx', 'KLL', 'B')
    API.new('EnumSystemCodePages', 'KL', 'L')
    API.new('EnumSystemLocales', 'KL', 'L')
    API.new('EnumTimeFormats', 'KLL', 'B')
    API.new('GetACP', 'V', 'I')
    API.new('GetCPInfo', 'LP', 'B')
    API.new('GetCPInfoEx', 'LLP', 'B')
    API.new('GetCurrencyFormat', 'LLPPPI', 'I')
    API.new('GetDateFormat', 'LLPPPI', 'I')
    API.new('GetLocaleInfo', 'LLPL', 'I')
    API.new('GetSystemDefaultLangID', 'V', 'L')
    API.new('GetSystemDefaultLCID', 'V', 'L')
    API.new('GetUserDefaultLangID', 'V', 'L')
    API.new('GetUserDefaultLCID', 'V', 'L')

    begin
      API.new('AdjustCalendarDate', 'PLP', 'B')
      API.new('EnumTimeFormatsEx', 'KSLP', 'B')
      API.new('GetCurrencyFormatEx', 'PLPPPI', 'I')
      API.new('GetDateFormatEx', 'SLPSPIS', 'I')
    rescue Win32::API::LoadLibraryError
      # Windows Vista or later
    end
    
    # Convenience method for converting the results of the GetACP()
    # function to a human readable string.
    # 
    def get_acp_string
      CODE_PAGE[GetACP.call]
    end
    
    # Equivalent of the MAKELCID macro in WinNT.h
    # 
    def MAKELCID(srtid, lgid)
      srtid << 16 | lgid
    end
    
    # Equivalent of the MAKELANGID macro in WinNT.h
    # 
    def MAKELANGID(x, s)
      s << 10 | x
    end
  end
end
