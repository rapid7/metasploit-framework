
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
	var os_lang;
	var browser_name;
	var browser_version;
	var useragent = navigator.userAgent;

	var version = "";
	version = useragent;
	
	//document.write("navigator.userAgent = '"+navigator.userAgent+"'<br>");
	//document.write("navigator.appVersion = '"+navigator.appVersion+"'<br>");

	// Firefox's appVersion on windows doesn't tell us the flavor, so use
	// userAgent all the time.  If userAgent is spoofed, appVersion will lie
	// also, so we don't lose anything by doing it this way.

	if (version.indexOf("Windows 95") != -1)          { os_name = "#{oses::WINDOWS}"; os_flavor = "95";    }
	else if (version.indexOf("Windows NT 4") != -1)   { os_name = "#{oses::WINDOWS}"; os_flavor = "NT";    }
	else if (version.indexOf("Win 9x 4.9") != -1)     { os_name = "#{oses::WINDOWS}"; os_flavor = "ME";    }
	else if (version.indexOf("Windows 98") != -1)     { os_name = "#{oses::WINDOWS}"; os_flavor = "98";    }
	else if (version.indexOf("Windows NT 5.0") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "2000";  }
	else if (version.indexOf("Windows NT 5.1") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "XP";    }
	else if (version.indexOf("Windows NT 5.2") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "2003";  }
	else if (version.indexOf("Windows NT 6.0") != -1) { os_name = "#{oses::WINDOWS}"; os_flavor = "Vista"; }
	else if (version.indexOf("Windows") != -1)        { os_name = "#{oses::WINDOWS}";                      }
	else if (version.indexOf("Mac") != -1)            { os_name = "#{oses::MAC_OSX}";                      }
	else if (version.indexOf("Linux") != -1)          { os_name = "#{oses::LINUX}";                        }

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

	if (window.opera) {
		browser_name = "#{clients::OPERA}";
	}
	
	if (typeof ScriptEngineMajorVersion == "function") {
		// then this is IE and we can detect the OS
		// TODO: add detection for IE on Mac.  low priority, since we don't have
		// any sploits for it yet and it's a very low market share
		os_name = "#{oses::WINDOWS}";
		browser_name = "#{clients::IE}";
		version = ScriptEngineMajorVersion().toString();
		version += ScriptEngineMinorVersion().toString();
		version += ScriptEngineBuildVersion().toString();
		//document.write("ScriptEngine: "+version+"<br />");
		switch (version){
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
				// IE 6.0.2600.0000, XP SP0 English
				os_flavor = "XP"; 
				os_sp = "SP0";
				break;
			case "568515":
				// IE 6.0.3790.0, 2003 Standard SP0 English
				os_flavor = "2003";
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
			case "575730":
				// IE 7.0.5730.13, Server 2003 Standard SP2 English
				// IE 7.0.5730.13, XP Professional SP2 English
				// rely on the user agent matching above to determine the OS,
				// but we know it's SP2 either way
				os_sp = "SP2";
				break;
		}
		if (!browser_version) {
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
		}
	}

	if (navigator.systemLanguage) {
		// ie
		os_lang = navigator.systemLanguage;
	} else if (navigator.language) {
		// gecko derivatives, safari, opera
		os_lang = navigator.language;
	} else {
		// some other browser and we don't know how to get the language, so
		// just guess english 
		os_lang = "en";
	}

	version = navigator.platform;
	if ( ("Win32" == version) || (version.match(/i.86/)) ) {
	    arch = "#{ARCH_X86}";
	} else if (-1 != version.indexOf('PPC'))  {
		arch = "#{ARCH_PPC}";
	}

	//document.write("Target is: "+os_name+" "+os_flavor+" "+os_sp+" "+os_lang+" / "+browser_name+" "+browser_version +"<br>");

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
				'useragent', 'version'
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
