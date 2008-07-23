
require 'rex/text'
require 'rex/exploitation/obfuscatejs'
require 'msf/core/auxiliary'

module Rex
module Exploitation

class JavascriptOSDetect < ObfuscateJS
	
	def initialize(custom_js = '', opts = {})
		clients = ::Msf::Auxiliary::Report::HttpClients
		oses    = ::Msf::Auxiliary::Report::OperatingSystems
		@js = custom_js
		@js = <<ENDJS + @js
/**
 * This can reliably detect browser versions for IE and Firefox even in the
 * presence of a spoofed User-Agent.  OS detection is more fragile and
 * requires truthful navigator.appVersion and navigator.userAgent strings in
 * order to be accurate for more than just IE on Windows.
 **/ 
function getVersion(){
	//Default values:
	var os_name;
	var os_flavor;
	var os_sp;
	var os_lang = "English";
	var browser_name;
	var browser_version;

	var ver = "";
	useragent = navigator.userAgent;
	ver = navigator.userAgent;
	
	document.write("navigator.userAgent = '"+navigator.userAgent+"'<br>");
	document.write("navigator.appVersion = '"+navigator.appVersion+"'<br>");

	// Firefox's appVersion on windows doesn't tell us the flavor, so use
	// userAgent all the time.  If userAgent is spoofed, appVersion will lie
	// also, so we don't lose anything by doing it this way.

	if (ver.indexOf("Windows 95") != -1)          { os_name = "#{oses::WINDOWS}"; os_flavor = "95";    }
	else if (ver.indexOf("Windows NT 4") != -1)   { os_name = "#{oses::WINDOWS}"; os_flavor = "NT";    }
	else if (ver.indexOf("Win 9x 4.9") != -1)     { os_name = "#{oses::WINDOWS}"; os_flavor = "ME";    }
	else if (ver.indexOf("Windows 98") != -1)     { os_name = "#{oses::WINDOWS}"; os_flavor = "98";    }
	else if (ver.indexOf("Windows NT 5.0") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "2000";  }
	else if (ver.indexOf("Windows NT 5.1") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "XP";    }
	else if (ver.indexOf("Windows NT 5.2") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "2003";  }
	else if (ver.indexOf("Windows NT 6.0") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "Vista"; }
	else if (ver.indexOf("Windows") != -1)        { os_name = "#{oses::WINDOWS}";                      }
	else if (ver.indexOf("Mac") != -1)            { os_name = "#{oses::MAC_OSX}";                      }
	else if (ver.indexOf("Linux") != -1)          { os_name = "#{oses::LINUX}";                        }

	if (os_name == "#{oses::LINUX}") {
		if (useragent.indexOf("Gentoo") != -1)         { os_flavor = "Gentoo";   }
		else if (useragent.indexOf("Ubuntu") != -1)    { os_flavor = "Ubuntu";   }
		else if (useragent.indexOf("Debian") != -1)    { os_flavor = "Debian";   }
		else if (useragent.indexOf("RHEL") != -1)      { os_flavor = "RHEL";     }
		else if (useragent.indexOf("CentOS") != -1)    { os_flavor = "CentOS";   }
	}

	if (window.getComputedStyle) {
		// Then this is a gecko derivative, assume firefox since that's the
		// only one we have sploits for.  We may need to revisit this in the
		// future.
		browser_name = "#{clients::FF}";
		if (document.getElementsByClassName) {
			browser_version = "3.0";
		} else if (window.Iterator) {
			browser_version = "2.0";
		} else if (Array.every) {
			browser_version = "1.5";
		} else {
			browser_version = "1.0";
		}
	}
	
	if (typeof ScriptEngineMajorVersion == "function") {
		// then this is IE and we can detect the OS
		// TODO: add detection for IE on Mac.  low priority, since we don't have
		// any sploits for it yet and it's a very low market share
		os_name = "#{oses::WINDOWS}";
		browser_name = "#{clients::IE}";
		if (document.documentElement && typeof document.documentElement.style.maxHeight!="undefined") {
			browser_version = "7.0";
		} else if (document.compatMode) { 
			browser_version = "6.0";
		} else if (window.createPopup) {
			browser_version = "5.5";
		} else if (window.attachEvent) {
			browser_version = "5.0";
		} else {
			browser_version = "4.0";
		}
		switch (navigator.appMinorVersion){
			case ";SP2;":
				browser_version += ";SP2";
				break;
		}
		ver = ScriptEngineMajorVersion().toString();
		ver += ScriptEngineMinorVersion().toString();
		ver += ScriptEngineBuildVersion().toString();
		document.write("ScriptEngine: "+ver+"<br />");
		switch (ver){
			case "514615":
				os_flavor = "2000";
				os_sp = "SP0";
				break;
			case "515907":
				os_flavor = "2000";
				os_sp = "SP3";	//or SP2: oCC.getComponentVersion('{22d6f312-b0f6-11d0-94ab-0080c74c7e95}', 'componentid') => 6,4,9,1109
				break;
			case "518513":
				os_flavor = "2000";
				os_sp = "SP4";
				break;
			case "566626":
				// found on 
				//   IE 6.0.2600.0000 
				//   XP SP0
				os_flaver = "XP"; 
				os_sp = "SP0";
				break;
			case "568827":
				os_flavor = "2003";
				os_sp = "SP1";
				break;
			case "568831":	//XP SP2 -OR- 2K SP4
				if (os_flavor == "2000"){
					os_sp = "SP4";
				}
				else{
					os_flavor = "XP";
					os_sp = "SP2";
				}
				break;
			case "568832":
				os_flavor = "2003";
				os_sp = "SP2";
				break;
		}
	}

	if (navigator.systemLanguage) {
		// ie
		ver = navigator.systemLanguage; 
	} else if (navigator.language) {
		// gecko derivatives
		ver = navigator.language; 
	} else {
		// some other browser and we don't know how to get the language, so
		// just guess english 
		ver = "en"; 
	}

	document.write("language = '"+ver+"'<br>");
	os_lang = ver;
	//switch (ver){
	//	case "fr": os_lang = "French";     break;
	//	case "zh": os_lang = "Chinese";    break;
	//	case "nl": os_lang = "Dutch";      break;
	//	case "de": os_lang = "German";     break;
	//	case "it": os_lang = "Italian";    break;
	//	case "ja": os_lang = "Japanese";   break;
	//	case "ko": os_lang = "Korean";     break;
	//	case "pl": os_lang = "Polish";     break;
	//	case "pt": os_lang = "Portuguese"; break;
	//	case "ru": os_lang = "Russian";    break;
	//	case "es": os_lang = "Spanish";    break;
	//	case "sv": os_lang = "Swedish";    break;
	//	case "tr": os_lang = "Turkish";    break;
	//	case "uk": os_lang = "Ukrainian";  break;
	//	case "vi": os_lang = "Vietnamese"; break;
	//	default:	//"en", "en-*"
	//		os_lang = "English"; break;
	//} // switch navigator.systemLanguage

	ver = navigator.platform;
	if ( ("Win32" == ver) || (ver.match(/i.86/)) ) {
	    arch = "#{ARCH_X86}";
	} else if (-1 != ver.indexOf('PPC'))  {
		arch = "#{ARCH_PPC}";
	}

	document.write("Target is: "+os_name+" "+os_flavor+" "+os_sp+" "+os_lang+" / "+browser_name+" "+browser_version +"<br>");

	return { os_name:os_name, os_flavor:os_flavor, os_sp:os_sp, os_lang:os_lang, arch:arch, browser_name:browser_name, browser_version:browser_version };
} // function getVersion
ENDJS
		super @js
		update_opts(opts) if (opts)
		update_opts({'Symbols' => {
			'Variables' => [ 
				'os_name', 'os_flavor',
				'os_sp', 'os_lang',
				'arch',
				'browser_name', 
				'browser_version', 
				'useragent', 'ver'
				],
			'Methods' => [ 'getVersion' ]
			}
		})

		#self.obfuscate

		return @js
	end

end
end

end
