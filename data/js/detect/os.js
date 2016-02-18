// Case matters, see lib/msf/core/constants.rb
// All of these should match up with constants in ::Msf::HttpClients
var clients_opera  = "Opera";
var clients_ie     = "MSIE";
var clients_ff     = "Firefox";
var clients_chrome = "Chrome";
var clients_safari = "Safari";

// All of these should match up with constants in ::Msf::OperatingSystems
var oses_linux     = "Linux";
var oses_android   = "Android";
var oses_windows   = "Windows";
var oses_mac_osx   = "Mac OS X";
var oses_apple_ios = "iOS";
var oses_freebsd   = "FreeBSD";
var oses_netbsd    = "NetBSD";
var oses_openbsd   = "OpenBSD";

// All of these should match up with the ARCH_* constants
var arch_armle    = "armle";
var arch_x86      = "x86";
var arch_x86_64   = "x86_64";
var arch_ppc      = "ppc";
var arch_mipsle   = "mipsle";

var os_detect = {};

/**
 * This can reliably detect browser versions for IE and Firefox even in the
 * presence of a spoofed User-Agent.  OS detection is more fragile and
 * requires truthful navigator.appVersion and navigator.userAgent strings in
 * order to be accurate for more than just IE on Windows.
 **/
os_detect.getVersion = function(){
	//Default values:
	var os_name;
	var os_vendor;
	var os_device;
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
	var unknown_fingerprint = null;

	var css_is_valid = function(prop, propCamelCase, css) {
		if (!document.createElement) return false;
		var d = document.createElement('div');
		d.setAttribute('style', prop+": "+css+";")
		return d.style[propCamelCase] === css;
	}

	var input_type_is_valid = function(input_type) {
		if (!document.createElement) return false;
		var input = document.createElement('input');
		input.setAttribute('type', input_type);
		return input.type == input_type;
	}

	//--
	// Client
	//--
	if (window.opera) {
		ua_name = clients_opera;
		if (!navigator.userAgent.match(/Opera/)) {
			ua_is_lying = true;
		}
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
				case "1347":  // Opera 9.80 / Ubuntu 10.10 (Karmic Koala)
				case "2091":  // opera-9.52-2091.gcc3-shared-qt3.i386.rpm
				case "2444":  // opera-9.60.gcc4-shared-qt3.i386.rpm
				case "2474":  // Opera 9.63 / Debian Testing (Lenny)
				case "4102":  // Opera 10.00 / Ubuntu 8.04 LTS (Hardy Heron)
				case "6386":  // 10.61
					os_name = oses_linux;
					break;
				case "1074":  // Opera 11.50 / Windows XP
				case "1100":  // Opera 11.52 / Windows XP
				case "3445":  // 10.61
				case "3516":  // Opera 10.63 / Windows XP
				case "7730":  // Opera 8.54 / Windows XP
				case "8502":  // "Opera 9 Eng Setup.exe"
				case "8679":  // "Opera_9.10_Eng_Setup.exe"
				case "8771":  // "Opera_9.20_Eng_Setup.exe"
				case "8776":  // "Opera_9.21_Eng_Setup.exe"
				case "8801":  // "Opera_9.22_Eng_Setup.exe"
				case "10108": // "Opera_952_10108_en.exe"
				case "10467": // "Opera_962_en_Setup.exe"
				case "10476": // Opera 9.63 / Windows XP
				case "WMD-50433": // Windows Mobile - "Mozilla/5.0 (Windows Mobile; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 10.00"
					os_name = oses_windows;
					break;
				case "2480":  // Opera 9.64 / FreeBSD 7.0
					os_name = oses_freebsd;
					break;
				case "6386":  // 10.61
					os_name = oses_mac_osx;
					break;
				case "1407":
					// In the case of mini versions, the UA is quite a bit
					// harder to spoof, so it's correspondingly easier to
					// trust. Unfortunately, despite being fairly truthful in
					// what OS it's running on, Opera mini seems to lie like a
					// rug in regards to the browser version.
					//
					// iPhone, iOS 5.0.1
					//  Opera/9.80 (iPhone; Opera Mini/7.1.32694/27.1407; U; en) Presto/2.8.119 Version/11.10.10
					// Android 2.3.6, opera mini 7.1
					//  Opera/9.80 (Android; Opera Mini/7.29530/27.1407; U; en) Presto/2.8.119 Version/11.101.10
					if (navigator.userAgent.indexOf("Android")) {
						os_name = oses_android;
					} else if (navigator.userAgent.indexOf("iPhone")) {
						os_name = oses_apple_ios;
						os_device = "iPhone";
					}
					break;
				// A few are ambiguous, record them here
				case "1250":
					// Opera 9.80 / Windows XP
					// Opera 11.61 / Windows XP
					// Opera 11.61 / Debian 4.0 (Etch)
					break;
				default:
					unknown_fingerprint = opera.buildNumber('inconspicuous');
					break;
			}
		}
	} else if (typeof window.onmousewheel != 'undefined' && ! (typeof ScriptEngineMajorVersion == 'function') ) { // IE 10 now has onmousewheel

		// Then this is webkit, could be Safari or Chrome.
		// Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1
		// Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Chrome/4.0.249.78 Safari/532.5
		// Mozilla/5.0 (Linux; U; Android 2.2; en-au; GT-I9000 Build/FROYO) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
		// Mozilla/5.0 (iPod; U; CPU iPhone OS 4_2_1 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Mobile/8C148
		// Mozilla/5.0 (iPad; U; CPU OS 3_2_1 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Mobile/7B405
		// Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543a Safari/419.3

		// Google Chrome has window.google (older versions), window.chromium (older versions), and window.window.chrome (3+)
		if (window.chromium || window.google || window.chrome) {
			ua_name = clients_chrome;
			search = "Chrome";
		} else {
			ua_name = clients_safari;
			search = "Version";
		}

		platform = navigator.platform.toLowerCase();
		// Just to be a pain, iPod and iPad both leave off "Safari" and
		// "Version" in the UA, see example above.  Grab the webkit version
		// instead.  =/
		if (platform.match(/ipod/)) {
			os_name = oses_apple_ios;
			os_device = "iPod";
			arch = arch_armle;
			search = "AppleWebKit";
		} else if (platform.match(/ipad/)) {
			os_name = oses_apple_ios;
			os_device = "iPad";
			arch = arch_armle;
			search = "AppleWebKit";
		} else if (platform.match(/iphone/)) {
			os_name = oses_apple_ios;
			os_device = "iPhone";
			arch = arch_armle;
		} else if (platform.match(/macintel/)) {
			os_name = oses_mac_osx;
			arch = arch_x86;
		} else if (platform.match(/linux/)) {
			os_name = oses_linux;

			if (platform.match(/x86_64/)) {
				arch = arch_x86_64;
			} else if (platform.match(/arm/)) {
				arch = arch_armle;
			} else if (platform.match(/x86/)) {
				arch = arch_x86;
			} else if (platform.match(/mips/)) {
				arch = arch_mipsle;
			}

			// Android overrides Linux
			if (navigator.userAgent.match(/android/i)) {
				os_name = oses_android;
			}
		} else if (platform.match(/windows/)) {
			os_name = oses_windows;
		}

		ua_version = this.searchVersion(search, navigator.userAgent);
		if (!ua_version || 0 == ua_version.length) {
			ua_is_lying = true;
		}
	} else if (navigator.oscpu && !document.all && navigator.taintEnabled || 'MozBlobBuilder' in window) {
		// Use taintEnabled to identify FF since other recent browsers
		// implement window.getComputedStyle now.  For some reason, checking for
		// taintEnabled seems to cause IE 6 to stop parsing, so make sure this
		// isn't IE first.

		// Also check MozBlobBuilder because FF 9.0.1 does not support taintEnabled

		// Then this is a Gecko derivative, assume Firefox since that's the
		// only one we have sploits for.  We may need to revisit this in the
		// future.  This works for multi/browser/mozilla_compareto against
		// Firefox and Mozilla, so it's probably good enough for now.
		ua_name = clients_ff;
		// Thanks to developer.mozilla.org "Firefox for developers" series for most
		// of these.
		// Release changelogs: http://www.mozilla.org/en-US/firefox/releases/
		if ('closest' in Element.prototype) {
			ua_version = '35.0';
		} else if ('matches' in Element.prototype) {
			ua_version = '34.0';
		} else if ('RadioNodeList' in window) {
			ua_version = '33.0';
		} else if ('copyWithin' in Array.prototype) {
			ua_version = '32.0';
		} else if ('fill' in Array.prototype) {
			ua_version = '31.0';
		} else if (css_is_valid('background-blend-mode', 'backgroundBlendMode', 'multiply')) {
			ua_version = '30.0';
		} else if (css_is_valid('box-sizing', 'boxSizing', 'border-box')) {
			ua_version = '29.0';
		} else if (css_is_valid('flex-wrap', 'flexWrap', 'nowrap')) {
			ua_version = '28.0';
		} else if (css_is_valid('cursor', 'cursor', 'grab')) {
			ua_version = '27.0';
		} else if (css_is_valid('image-orientation',
		                 'imageOrientation',
		                 '0deg')) {
			ua_version = '26.0';
		} else if (css_is_valid('background-attachment',
		                 'backgroundAttachment',
		                 'local')) {
			ua_version = '25.0';
		} else if ('DeviceStorage' in window && window.DeviceStorage &&
				'default' in window.DeviceStorage.prototype) {
			// https://bugzilla.mozilla.org/show_bug.cgi?id=874213
			ua_version = '24.0';
		} else if (input_type_is_valid('range')) {
			ua_version = '23.0';
		} else if ('HTMLTimeElement' in window) {
			ua_version = '22.0';
		} else if ('createElement' in document &&
		           document.createElement('main') &&
		           document.createElement('main').constructor === window['HTMLElement']) {
			ua_version = '21.0';
		} else if ('imul' in Math) {
			ua_version = '20.0';
		} else if (css_is_valid('font-size', 'fontSize', '23vmax')) {
			ua_version = '19.0';
		} else if ('devicePixelRatio' in window) {
			ua_version = '18.0';
		} else if ('createElement' in document &&
		           document.createElement('iframe') &&
		           'sandbox' in document.createElement('iframe')) {
			ua_version = '17.0';
		} else if ('mozApps' in navigator && 'install' in navigator.mozApps) {
			ua_version = '16.0';
		} else if ('HTMLSourceElement' in window &&
		           HTMLSourceElement.prototype &&
		           'media' in HTMLSourceElement.prototype) {
			ua_version = '15.0';
		} else if ('mozRequestPointerLock' in document.body) {
			ua_version = '14.0';
		} else if ('Map' in window) {
			ua_version = "13.0";
		} else if ('mozConnection' in navigator) {
			ua_version = "12.0";
		} else if ('mozVibrate' in navigator) {
			ua_version = "11.0";
		} else if (css_is_valid('-moz-backface-visibility', 'MozBackfaceVisibility', 'hidden')) {
			ua_version = "10.0";
		} else if ('doNotTrack' in navigator) {
			ua_version = "9.0";
		} else if ('insertAdjacentHTML' in document.body) {
			ua_version = "8.0";
		} else if ('ondeviceorientation' in window && !('createEntityReference' in document)) {
			ua_version = "7.0";
		} else if ('MozBlobBuilder' in window) {
			ua_version = "6.0";
		} else if ('isGenerator' in Function) {
			ua_version = "5.0";
		} else if ('isArray' in Array) {
			ua_version = "4.0";
		} else if (document.readyState) {
			ua_version = "3.6";
		} else if (String.trimRight) {
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
		if (navigator.oscpu != navigator.platform) {
			ua_is_lying = true;
		}
		// oscpu is unaffected by changes in the useragent and has values like:
		//    "Linux i686"
		//    "Windows NT 6.0"
		// haven't tested on 64-bit Windows
		version = navigator.oscpu;
		if (version.match(/i.86/)) {
			arch = arch_x86;
		}
		if (version.match(/x86_64/)) {
			arch = arch_x86_64;
		}
		if (version.match(/Windows/)) {
			os_name = oses_windows;
			// Technically these will mismatch server OS editions, but those are
			// rarely used as client systems and typically have the same exploit
			// characteristics as the associated client.
			switch(version) {
				case "Windows NT 5.0": os_name = "Windows 2000"; break;
				case "Windows NT 5.1": os_name = "Windows XP"; break;
				case "Windows NT 5.2": os_name = "Windows 2003"; break;
				case "Windows NT 6.0": os_name = "Windows Vista"; break;
				case "Windows NT 6.1": os_name = "Windows 7"; break;
				case "Windows NT 6.2": os_name = "Windows 8"; break;
				case "Windows NT 6.3": os_name = "Windows 8.1"; break;
			}
		}
		if (version.match(/Linux/)) {
			os_name = oses_linux;
		}
		// end navigator.oscpu checks
  } else if (typeof ScriptEngineMajorVersion == "function") {
		// Then this is IE and we can very reliably detect the OS.
		// Need to add detection for IE on Mac.  Low priority, since we
		// don't have any sploits for it yet and it's a very low market
		// share.
		os_name = oses_windows;
		ua_name = clients_ie;
		version_maj   = ScriptEngineMajorVersion().toString();
		version_min   = ScriptEngineMinorVersion().toString();
		version_build = ScriptEngineBuildVersion().toString();

		version = version_maj + version_min + version_build;

		//document.write("ScriptEngine: "+version+"<br />");
		switch (version){
			case "514615":
				// IE 5.00.2920.0000, 2000 Advanced Server SP0 English
				ua_version = "5.0";
				os_name = "Windows 2000";
				os_sp = "SP0";
				break;
			case "515907":
				os_name = "Windows 2000";
				os_sp = "SP3";	//or SP2: oCC.getComponentVersion('{22d6f312-b0f6-11d0-94ab-0080c74c7e95}', 'componentid') => 6,4,9,1109
				break;
			case "518513":
				os_name = "Windows 2000";
				os_sp = "SP4";
				break;
			case "566626":
				// IE 6.0.2600.0000, XP SP0 English
				// IE 6.0.2800.1106, XP SP1 English
				ua_version = "6.0";
				os_name = "Windows XP";
				os_sp = "SP0";
				break;
			case "568515":
				// IE 6.0.3790.0, 2003 Standard SP0 English
				ua_version = "6.0";
				os_name = "Windows 2003";
				os_sp = "SP0";
				break;
			case "568820":
				// IE 6.0.2900.2180, xp sp2 english
				os_name = "Windows XP";
				os_sp = "SP2";
				break;
			case "568827":
				os_name = "Windows 2003";
				os_sp = "SP1";
				break;
			case "568831":	//XP SP2 -OR- 2K SP4
				if (os_name == "2000"){
					os_sp = "SP4";
				}
				else{
					os_name = "Windows XP";
					os_sp = "SP2";
				}
				break;
			case "568832":
				os_name = "Windows 2003";
				os_sp = "SP2";
				break;
			case "568837":
				// IE 6.0.2900.2180, XP Professional SP2 Korean
				ua_version = "6.0";
				os_name = "Windows XP";
				os_sp = "SP2";
				break;
			case "5716599":
				// IE 7.0.5730.13, XP Professional SP3 English
				// IE 6.0.2900.5512, XP Professional SP3 English
				// IE 6.0.2900.5512, XP Professional SP3 Spanish
				//
				// Since this scriptengine applies to more than one major version of
				// IE, rely on the object detection below to determine ua_version.
				//ua_version = "6.0";
				os_name = "Windows XP";
				os_sp = "SP3";
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
				os_name = "Windows XP";
				os_sp = "SP3";
				break;
			case "5722589":
				// IE 7.0.5730.13, XP Professional SP3 English
				ua_version = "7.0";
				os_name = "Windows XP";
				os_sp = "SP3";
				break;
			case "576000":
				// IE 7.0.6000.16386, Vista Ultimate SP0 English
				ua_version = "7.0";
				os_name = "Windows Vista";
				os_sp = "SP0";
				break;
			case "580":
				// IE 8.0.7100.0, Windows 7 English
				// IE 8.0.7100.0, Windows 7 64-bit English
			case "5816385":
				// IE 8.0.7600.16385, Windows 7 English
			case "5816475":
			case "5816762":
				// IE 8.0.7600.16385, Windows 7 English
				ua_version = "8.0";
				os_name = "Windows 7";
				os_sp = "SP0";
				break;
			case "5817514":
				// IE 8.0.7600.17514, Windows 7 SP1 English
				ua_version = "8.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "5818702":
				// IE 8.0.6001.18702, XP Professional SP3 English
			case "5822960":
				// IE 8.0.6001.18702, XP Professional SP3 Greek
				ua_version = "8.0";
				os_name = "Windows XP";
				os_sp = "SP3";
				break;
			case "9016406":
				// IE 9.0.7930.16406, Windows 7 64-bit
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP0";
				break;
			case "9016441":
				// IE 9.0.8112.16421, Windows 7 32-bit English
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016443":
				// IE 9.0.8112.16421, Windows 7 Polish
				// Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016446":
				// IE 9.0.8112.16421, Windows 7 English (Update Versions: 9.0.7 (KB2699988)
				// Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; MASA; InfoPath.3; MS-RTC LM 8; BRI/2)Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; MASA; InfoPath.3; MS-RTC LM 8; BRI/2)
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016464":
				// browsershots.org, MSIE 7.0 / Windows 2008 R2
				os_name = "Windows 2008 R2";
				ua_version = "9.0";
				break;
			case "9016470":
				// IE 9.0.8112.16421 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016502":
				// IE 9.0.8112.16502 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016506":
				// IE 9.0.8112.16506 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016514":
				// IE 9.0.8112.16514 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016520":
				// IE 9.0.8112.16520 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016526":
				// IE 9.0.8112.16526 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "9016533":
				// IE 9.0.8112.16533 / Windows 7 SP1
				ua_version = "9.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "10016720":
				// IE 10.0.9200.16721 / Windows 7 SP1
				ua_version = "10.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "11016428":
				// IE 11.0.9600.16428 / Windows 7 SP1
				ua_version = "11.0";
				os_name = "Windows 7";
				os_sp = "SP1";
				break;
			case "10016384":
				// IE 10.0.9200.16384 / Windows 8 x86
				ua_version = "10.0";
				os_name = "Windows 8";
				os_sp = "SP0";
				break;
			case "11016426":
				// IE 11.0.9600.16476 / KB2898785 (Technically: 11.0.2) Windows 8.1 x86 English
				ua_version = "11.0";
				os_name = "Windows 8.1";
				break;
			case "1000":
				// IE 10.0.8400.0 (Pre-release + KB2702844), Windows 8 x86 English Pre-release
				ua_version = "10.0";
				os_name = "Windows 8";
				os_sp = "SP0";
				break;
			case "1100":
				// IE 11.0.10011.0 Windows 10.0 (Build 10074) English - insider preview
				ua_version = "11.0";
				os_name = "Windows 10";
				os_sp = "SP0";
				break;
			default:
				unknown_fingerprint = version;
				break;
		}

		if (!ua_version) {
			// The ScriptEngine functions failed us, try some object detection
			if (document.documentElement && (typeof document.documentElement.style.maxHeight)!="undefined") {
				// IE 11 detection, see: http://msdn.microsoft.com/en-us/library/ie/bg182625(v=vs.85).aspx
				try {
					if (document.__proto__ != undefined) { ua_version = "11.0"; }
				} catch (e) {}

				// IE 10 detection using nodeName
				if (!ua_version) {
					try {
						var badNode = document.createElement && document.createElement("badname");
						if (badNode && badNode.nodeName === "BADNAME") { ua_version = "10.0"; }
					} catch(e) {}
				}

				// IE 9 detection based on a "Object doesn't support property or method" error
				if (!ua_version) {
					try {
						document.BADNAME();
					} catch(e) {
						if (e.message.indexOf("BADNAME") > 0) {
							ua_version = "9.0";
						}
					}
				}

				// IE8 detection straight from IEBlog.  Thank you Microsoft.
				if (!ua_version) {
					try {
						ua_version = "8.0";
						document.documentElement.style.display = "table-cell";
					} catch(e) {
						// This executes in IE7,
						// but not IE8, regardless of mode
						ua_version = "7.0";
					}
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
					os_sp = "SP2";
					break;
			}
		}
	}

	if (!os_name && navigator.platform == "Win32") { os_name = oses_windows; }

	//--
	// Figure out the type of Windows
	//--
	if (!ua_is_lying) {
		version = useragent.toLowerCase();
	} else if (navigator.oscpu) {
		// Then this is Gecko and we can get at least os_name without the
		// useragent
		version = navigator.oscpu.toLowerCase();
	} else {
		// All we have left is the useragent and we know it's lying, so don't bother
		version = " ";
	}
	if (!os_name || 0 == os_name.length) {
		if (version.indexOf("windows") != -1)    { os_name = oses_windows; }
		else if (version.indexOf("mac") != -1)   { os_name = oses_mac_osx; }
		else if (version.indexOf("linux") != -1) { os_name = oses_linux;   }
	}
	if (os_name == oses_windows) {
		if (version.indexOf("windows 95") != -1)          { os_name = "Windows 95";    }
		else if (version.indexOf("windows nt 4") != -1)   { os_name = "Windows NT";    }
		else if (version.indexOf("win 9x 4.9") != -1)     { os_name = "Windows ME";    }
		else if (version.indexOf("windows 98") != -1)     { os_name = "Windows 98";    }
		else if (version.indexOf("windows nt 5.0") != -1) { os_name = "Windows 2000";  }
		else if (version.indexOf("windows nt 5.1") != -1) { os_name = "Windows XP";    }
		else if (version.indexOf("windows nt 5.2") != -1) { os_name = "Windows 2003";  }
		else if (version.indexOf("windows nt 6.0") != -1) { os_name = "Windows Vista"; }
		else if (version.indexOf("windows nt 6.1") != -1) { os_name = "Windows 7";     }
		else if (version.indexOf("windows nt 6.2") != -1) { os_name = "Windows 8";     }
		else if (version.indexOf("windows nt 6.3") != -1) { os_name = "Windows 8.1";   }
	}
	if (os_name == oses_linux && (!os_vendor || 0 == os_vendor.length)) {
		if (version.indexOf("gentoo") != -1)       { os_vendor = "Gentoo";  }
		else if (version.indexOf("ubuntu") != -1)  { os_vendor = "Ubuntu";  }
		else if (version.indexOf("debian") != -1)  { os_vendor = "Debian";  }
		else if (version.indexOf("rhel") != -1)    { os_vendor = "RHEL";    }
		else if (version.indexOf("red hat") != -1) { os_vendor = "RHEL";    }
		else if (version.indexOf("centos") != -1)  { os_vendor = "CentOS";  }
		else if (version.indexOf("fedora") != -1)  { os_vendor = "Fedora";  }
		else if (version.indexOf("android") != -1) { os_vendor = "Android"; }
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
	if (typeof(navigator.cpuClass) != 'undefined') {
		// Then this is IE or Opera9+ and we can grab the arch directly
		switch (navigator.cpuClass) {
			case "x86":
				arch = arch_x86;
				break;
			case "x64":
				arch = arch_x86_64;
				break;
		}
	}
	if (!arch || 0 == arch.length) {
		// We don't have the handy-dandy navagator.cpuClass, so infer from
		// platform
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
			arch = arch_x86;
		} else if (-1 != version.indexOf('x64') || (-1 != version.indexOf('x86_64')))  {
			arch = arch_x86_64;
		} else if (-1 != version.indexOf('PPC'))  {
			arch = arch_ppc;
		}
	}

	this.ua_is_lying = ua_is_lying;
	this.os_name = os_name;
	this.os_vendor = os_vendor;
	this.os_flavor = os_flavor;
	this.os_device = os_device;
	this.os_sp = os_sp;
	this.os_lang = os_lang;
	this.arch = arch;
	this.ua_name = ua_name;
	this.ua_version = ua_version;
	this.ua_version = ua_version;

	return { os_name:os_name, os_vendor:os_vendor, os_flavor:os_flavor, os_device:os_device, os_sp:os_sp, os_lang:os_lang, arch:arch, ua_name:ua_name, ua_version:ua_version };
}; // function getVersion

os_detect.searchVersion = function(needle, haystack) {
	var index = haystack.indexOf(needle);
	var found_version;
	if (index == -1) { return; }
	found_version = haystack.substring(index+needle.length+1);
	if (found_version.indexOf(' ') != -1) {
		// Strip off any junk at the end such as a CLR declaration
		found_version = found_version.substring(0,found_version.indexOf(' '));
	}
	return found_version;
};


/*
 * Return -1 if a < b, 0 if a == b, 1 if a > b
 */
ua_ver_cmp = function(ver_a, ver_b) {
	// shortcut the easy case
	if (ver_a == ver_b) {
		return 0;
	}

	a = ver_a.split(".");
	b = ver_b.split(".");
	for (var i = 0; i < Math.max(a.length, b.length); i++) {
		// 3.0 == 3
		if (!b[i]) { b[i] = "0"; }
		if (!a[i]) { a[i] = "0"; }

		if (a[i] == b[i]) { continue; }

		a_int = parseInt(a[i]);
		b_int = parseInt(b[i]);
		a_rest = a[i].substr(a_int.toString().length);
		b_rest = b[i].substr(b_int.toString().length);
		if (a_int < b_int) {
			return -1;
		} else if (a_int > b_int) {
			return 1;
		} else { // ==
			// Then we need to deal with the stuff after the ints, e.g.:
			// "b4pre"
			if (a_rest == "b" && b_rest.length == 0) {
				return -1;
			}
			if (b_rest == "b" && a_rest.length == 0) {
				return 1;
			}
			// Just give up and try a lexicographical comparison
			if (a_rest < b_rest) {
				return -1;
			} else if (a_rest > b_rest) {
				return 1;
			}
		}
	}
	// If we get here, they must be equal
	return 0;
};

ua_ver_lt = function(a, b) {
	if (-1 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
ua_ver_gt = function(a, b) {
	if (1 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
ua_ver_eq = function(a, b) {
	if (0 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
