
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
	var ua_name;
	var ua_version;
	var arch = "";
	var useragent = navigator.userAgent;
	// Trust but verify...
	var ua_is_lying = false;

	var version = "";

	//--
	// Client
	//--
	if (window.opera) {
		ua_name = "#{clients::OPERA}";
		// This seems to be completely accurate, e.g. "9.21" is the return
		// value of opera.version() when run on Opera 9.21
		ua_version = opera.version();
		if (!os_name) {
			// The 'inconspicuous' argument is there to give us a real value on
			// Opera 6 where, without it, the return value is supposedly 
			// 'Hm, were you only as smart as Bjorn Vermo...'
			// though I have not verfied this claim.
			switch (opera.buildNumber('inconspicuous')) {
				case "344":   // opera-9.0-20060616.1-static-qt.i386-en-344
				case "2091":  // opera-9.52-2091.gcc3-shared-qt3.i386.rpm
				case "2444":  // opera-9.60.gcc4-shared-qt3.i386.rpm
					os_name = "#{oses::LINUX}";
					break;
				case "8502":  // "Opera 9 Eng Setup.exe"
				case "8679":  // "Opera_9.10_Eng_Setup.exe"
				case "8771":  // "Opera_9.20_Eng_Setup.exe"
				case "8776":  // "Opera_9.21_Eng_Setup.exe"
				case "8801":  // "Opera_9.22_Eng_Setup.exe"
				case "10108": // "Opera_952_10108_en.exe"
				case "10467": // "Opera_962_en_Setup.exe"
					os_name = "#{oses::WINDOWS}";
					break;
			}
		}
	} else if (typeof window.onmousewheel != 'undefined') {
		// XXX Flesh this out.
		ua_name = "#{clients::SAFARI}";
		// Unlike every body else, the version isn't after the browser's
		// name.  That's where it puts Webkit's version.  The real version is
		// after "Version".  e.g.:
		// Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1
		ua_version = searchVersion("Version", navigator.userAgent);
		if (!ua_version || 0 == ua_version.length) {
			ua_is_lying = true;
		}
	} else if (!document.all && navigator.taintEnabled) {
		// Use taintEnabled to identify FF since other recent browsers
		// implement window.getComputedStyle now.  For some reason, checking for
		// taintEnabled seems to cause IE 6 to stop parsing, so make sure this
		// isn't IE first.
		// 
		// Then this is a Gecko derivative, assume Firefox since that's the
		// only one we have sploits for.  We may need to revisit this in the
		// future.  This works for multi/browser/mozilla_compareto against
		// Firefox and Mozilla, so it's probably good enough for now.
		ua_name = "#{clients::FF}";
		if (String.trimRight) {
			ua_version = "3.5";
		} else if (document.getElementsByClassName) {
			ua_version = "3";
		} else if (window.Iterator) {
			ua_version = "2";
		} else if (Array.every) {
			ua_version = "1.5";
		} else {
			ua_version = "1";
		}

		// oscpu is unaffected by changes in the useragent and has values like:
		//    "Linux i686"
		//    "Windows NT 6.0"
		// haven't tested on 64-bit Windows
		version = navigator.oscpu;
		os_name = version.split(' ')[0];
		if (version.match(/i.86/)) {
			arch = "#{ARCH_X86}";
		}

		// Verify whether the ua string is lying by checking the major version
		// number against what we detected using known objects above.  If it
		// appears to be truthful, then use its more precise version number.
		version = searchVersion("Firefox", navigator.userAgent);
		if (version && version.substr(0,ua_version.length) == ua_version) {
			// The version number will end with a space or end of line, so strip
			// off anything after a space if one exists
			if (-1 != version.indexOf(" ")) {
				version = version.substr(0,version.indexOf(" "));
			}
			ua_version = version;
		} else {
			ua_is_lying = true;
		}

	} else if (typeof ScriptEngineMajorVersion == "function") {
		// Then this is IE and we can very reliably detect the OS.
		// Need to add detection for IE on Mac.  Low priority, since we
		// don't have any sploits for it yet and it's a very low market
		// share.
		os_name = "#{oses::WINDOWS}";
		ua_name = "#{clients::IE}";
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
				ua_version = "6.0";
				os_flavor = "XP"; 
				os_sp = "SP0";
				break;
			case "568515":
				// IE 6.0.3790.0, 2003 Standard SP0 English
				ua_version = "6.0";
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
				// IE 7.0.5730.13, Server 2003 Standard SP1 English
				// IE 7.0.5730.13, XP Professional SP2 English
				// Rely on the user agent matching above to determine the OS.
				// This will incorrectly identify 2k3 SP1 as SP2
				ua_version = "7.0";
				os_sp = "SP2";
				break;
			case "5718066":
				// IE 7.0.5730.13, XP Professional SP3 English
				ua_version = "7.0";
				os_flavor = "XP";
				os_sp = "SP3";
				break;
			case "5818702":
				// IE 8.0.6001.18702, XP Professional SP3 English
				ua_version = "8.0";
				os_flavor = "XP";
				os_sp = "SP3";
				break;
			case "580":
				// IE 8.0.7100.0, Windows 7 English
				// IE 8.0.7100.0, Windows 7 64-bit English
				ua_version = "8.0";
				os_flavor = "7";
				os_sp = "SP0";
				break;
		}
		if (!ua_version) {
			if (document.documentElement && (typeof document.documentElement.style.maxHeight)!="undefined") {
				// IE8 detection straight from IEBlog.  Thank you Microsoft.
				try {
					ua_version = "8.0";
					document.documentElement.style.display = "table-cell";
				} catch(e) {
					// This executes in IE7,
					// but not IE8, regardless of mode
					ua_version = "7.0";
				}
			} else if (document.compatMode) { 
				ua_version = "6.0";
			} else if (window.createPopup) {
				ua_version = "5.5";
			} else if (window.attachEvent) {
				ua_version = "5.0";
			} else {
				ua_version = "4.0";
			}
			switch (navigator.appMinorVersion){
				case ";SP2;":
					ua_version += ";SP2";
					break;
			}
		}
	}

	//--
	// Flavor
	//--
	if (navigator.oscpu) {
		// Then this is Gecko and we can do it without the useragent
		version = navigator.oscpu.toLowerCase();
	} else if (!ua_is_lying) {
		version = useragent.toLowerCase();
	} else { 
		// All we have left is the useragent and we know it's lying, so don't bother
		version = " ";
	}
	if (!os_name || 0 == os_name.length) {
		if (version.indexOf("windows") != -1)    { os_name = "#{oses::WINDOWS}"; }
		else if (version.indexOf("mac") != -1)   { os_name = "#{oses::MAC_OSX}"; }
		else if (version.indexOf("linux") != -1) { os_name = "#{oses::LINUX}";   }
	}
	if (os_name == "#{oses::WINDOWS}" && (!os_flavor || 0 == os_flavor.length)) {
		if (version.indexOf("windows 95") != -1)          { os_flavor = "95";    }
		else if (version.indexOf("windows nt 4") != -1)   { os_flavor = "NT";    }
		else if (version.indexOf("win 9x 4.9") != -1)     { os_flavor = "ME";    }
		else if (version.indexOf("windows 98") != -1)     { os_flavor = "98";    }
		else if (version.indexOf("windows nt 5.0") != -1) { os_flavor = "2000";  }
		else if (version.indexOf("windows nt 5.1") != -1) { os_flavor = "XP";    }
		else if (version.indexOf("windows nt 5.2") != -1) { os_flavor = "2003";  }
		else if (version.indexOf("windows nt 6.0") != -1) { os_flavor = "Vista"; }
		else if (version.indexOf("windows nt 6.1") != -1) { os_flavor = "7";     }
	}
	if (os_name == "#{oses::LINUX}" && (!os_flavor || 0 == os_flavor.length)) {
		if (version.indexOf("gentoo") != -1)      { os_flavor = "Gentoo"; }
		else if (version.indexOf("ubuntu") != -1) { os_flavor = "Ubuntu"; }
		else if (version.indexOf("debian") != -1) { os_flavor = "Debian"; }
		else if (version.indexOf("rhel") != -1)   { os_flavor = "RHEL";   }
		else if (version.indexOf("red hat") != -1){ os_flavor = "RHEL";   }
		else if (version.indexOf("centos") != -1) { os_flavor = "CentOS"; }
	}

	//--
	// Language 
	//--
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

	//--
	// Architecture 
	//--
	if (!arch || 0 == arch.length) {
		version = navigator.platform;
		//document.write(version + "\\n");
		// IE 8 does a bit of wacky user-agent switching for "Compatibility View"; 
		// 64-bit client on Windows 7, 64-bit:
		//     Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0)
		// 32-bit client on Windows 7, 64-bit:
		//     Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0)
		// 32-bit client on Vista, 32-bit, "Compatibility View":
		//     Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0)
		//
		// Report 32-bit client on 64-bit OS as being 32 because exploits will
		// need to know the bittedness of the process, not the OS.
		if ( ("Win32" == version) || (version.match(/i.86/)) ) {
			arch = "#{ARCH_X86}";
		} else if (-1 != version.indexOf('x64') || (-1 != version.indexOf('x86_64')))  {
			arch = "#{ARCH_X86_64}";
		} else if (-1 != version.indexOf('PPC'))  {
			arch = "#{ARCH_PPC}";
		}
	}

	return { os_name:os_name, os_flavor:os_flavor, os_sp:os_sp, os_lang:os_lang, arch:arch, ua_name:ua_name, ua_version:ua_version };
} // function getVersion
function searchVersion(needle, haystack) {
	var index = haystack.indexOf(needle);
	var found_version;
	if (index == -1) { return; }
	found_version = haystack.substring(index+needle.length+1);
	// Strip off any junk at the end such as a CLR declaration
	found_version = found_version.substring(0,found_version.indexOf(' '));
	return found_version;
}
ENDJS
		super @js
		update_opts(opts) if (opts)
		update_opts({'Symbols' => {
			'Variables' => [ 
				'os_name', 'os_flavor',
				'os_sp', 'os_lang',
				'arch',
				'ua_name', 
				'ua_version', 
				'found_version', 
				'needle', 
				'haystack',
				],
			'Methods' => [ 'getVersion', 'searchVersion' ]
			}
		})

		#self.obfuscate

		return @js
	end

end
end

end
