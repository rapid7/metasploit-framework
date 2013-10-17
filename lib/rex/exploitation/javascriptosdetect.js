
// Case matters, see lib/msf/core/constants.rb
// All of these should match up with constants in ::Msf::HttpClients
clients_opera = "Opera";
clients_ie    = "MSIE";
clients_ff    = "Firefox";
clients_chrome= "Chrome";
clients_safari= "Safari";

// All of these should match up with constants in ::Msf::OperatingSystems
oses_linux    = "Linux";
oses_windows  = "Microsoft Windows";
oses_mac_osx  = "Mac OS X";
oses_freebsd  = "FreeBSD";
oses_netbsd   = "NetBSD";
oses_openbsd  = "OpenBSD";

// All of these should match up with the ARCH_* constants
arch_armle    = "armle";
arch_x86      = "x86";
arch_x86_64   = "x86_64";
arch_ppc      = "ppc";

window.os_detect = {};

/**
 * This can reliably detect browser versions for IE and Firefox even in the
 * presence of a spoofed User-Agent.  OS detection is more fragile and
 * requires truthful navigator.appVersion and navigator.userAgent strings in
 * order to be accurate for more than just IE on Windows.
 **/
window.os_detect.getVersion = function(){
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
						os_name = oses_linux;
						os_flavor = "Android";
					} else if (navigator.userAgent.indexOf("iPhone")) {
						os_name = oses_mac_osx;
						os_flavor = "iPhone";
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
			os_name = oses_mac_osx;
			os_flavor = "iPod";
			arch = arch_armle;
			search = "AppleWebKit";
		} else if (platform.match(/ipad/)) {
			os_name = oses_mac_osx;
			os_flavor = "iPad";
			arch = arch_armle;
			search = "AppleWebKit";
		} else if (platform.match(/iphone/)) {
			os_name = oses_mac_osx;
			os_flavor = "iPhone";
			arch = arch_armle;
		} else if (platform.match(/macintel/)) {
			os_name = oses_mac_osx;
			arch = arch_x86;
		} else if (platform.match(/linux/)) {
			os_name = oses_linux;
			if (platform.match(/x86_64/)) {
				arch = arch_x86_64;
			} else if (platform.match(/arm/)) {
				// Android and maemo
				arch = arch_armle;
			}
		} else if (platform.match(/windows/)) {
			os_name = oses_windows;
		}

		ua_version = this.searchVersion(search, navigator.userAgent);
		if (!ua_version || 0 == ua_version.length) {
			ua_is_lying = true;
		}
	} else if (!document.all && navigator.taintEnabled ||
	            'MozBlobBuilder' in window) {
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
		if ('DeviceStorage' in window && window.DeviceStorage &&
				'default' in window.DeviceStorage.prototype) {
			// https://bugzilla.mozilla.org/show_bug.cgi?id=874213
			ua_version = '24.0'
		} else if (input_type_is_valid('range')) {
			ua_version = '23.0'
		} else if ('HTMLTimeElement' in window) {
			ua_version = '22.0'
		} else if ('createElement' in document &&
		           document.createElement('main') &&
		           document.createElement('main').constructor === window['HTMLElement']) {
			ua_version = '21.0'
		} else if ('imul' in Math) {
			ua_version = '20.0'
		} else if (css_is_valid('font-size', 'fontSize', '23vmax')) {
			ua_version = '19.0'
		} else if ('devicePixelRatio' in window) {
			ua_version = '18.0'
		} else if ('createElement' in document &&
		           document.createElement('iframe') &&
		           'sandbox' in document.createElement('iframe')) {
			ua_version = '17.0'
		} else if ('mozApps' in navigator && 'install' in navigator.mozApps) {
			ua_version = '16.0'
		} else if ('HTMLSourceElement' in window && 
		           HTMLSourceElement.prototype &&
		           'media' in HTMLSourceElement.prototype) {
			ua_version = '15.0'
		} else if ('mozRequestPointerLock' in document.body) {
			ua_version = '14.0'
		} else if ('Map' in window) {
			ua_version = "13.0"
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
			switch(version) {
				case "Windows NT 5.0": os_flavor = "2000"; break;
				case "Windows NT 5.1": os_flavor = "XP"; break;
				case "Windows NT 5.2": os_flavor = "2003"; break;
				case "Windows NT 6.0": os_flavor = "Vista"; break;
				case "Windows NT 6.1": os_flavor = "7"; break;
				case "Windows NT 6.2": os_flavor = "8"; break;
			}
		}
		if (version.match(/Linux/)) {
			os_name = oses_linux;
		}
		// end navigator.oscpu checks

		// buildID is unaffected by changes in the useragent and typically has
		// the compile date which in some cases can be used to map to specific
		// Version & O/S (including Distro and even Arch). Depending upon the
		// buildID, sometime navigator.productSub will be needed.
		//
		// This technique, and the laboriously compiled associated table,
		// submitted by Mark Fioravanti.

		var buildid = navigator.buildID;

		switch(buildid) {
			case "2008041514": ua_version = "3.0.0.b5"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2008041515": ua_version = "3.0.0.b5"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "2008052312": ua_version = "3.0.0"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2008052906": ua_version = "3.0.0"; os_name = oses_windows; break;
			case "2008052909": ua_version = "3.0.0.rc1"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2008052912": ua_version = "3.0.0"; os_name = oses_linux; break;
			case "2008060309": ua_version = "3.0.0"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "2008070205": ua_version = "2.0.0.16"; os_name = oses_windows; break;
			case "2008070206": ua_version = "3.0.1"; os_name = oses_linux; break;
			case "2008070208": ua_version = "3.0.1"; os_name = oses_windows; break;
			case "2008071222": ua_version = "3.0.1"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2008072820":
				switch (navigator.productSub) {
					case "2008072820": ua_version = "3.0.1"; os_name = oses_linux; break;
					case "2008092313": ua_version = "3.0.2"; os_name = oses_linux; break;
				} break;
			case "2008082909": ua_version = "2.0.0.17"; os_name = oses_windows; break;
			case "2008091618": ua_version = "3.0.2"; os_name = oses_linux; break;
			case "2008091620": ua_version = "3.0.2"; os_name = oses_windows; break;
			case "2008092313": ua_version = "3.0.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2008092416": ua_version = "3.0.3"; os_name = oses_linux; break;
			case "2008092417": ua_version = "3.0.3"; os_name = oses_windows; break;
			case "2008092510": ua_version = "3.0.4"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2008101315":
				switch (navigator.productSub) {
					case "2008101315": ua_version = "3.0.3"; os_name = oses_linux; break;
					case "2008111318": ua_version = "3.0.4"; os_name = oses_linux; arch = arch_x86; break;
				} break;
			case "2008102918": ua_version = "2.0.0.18"; os_name = oses_windows; break;
			case "2008102920": ua_version = "3.0.4"; break;
			case "2008112309": ua_version = "3.0.4"; os_name = oses_linux; os_flavor = "Debian"; break; // browsershots: Iceweasel 3.0.4 / Debian Testing (Lenny)
			case "2008111317": ua_version = "3.0.5"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2008111318": ua_version = "3.0.5"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "2008120119": ua_version = "2.0.0.19"; os_name = oses_windows; break;
			case "2008120121": ua_version = "3.0.5"; os_name = oses_linux; break;
			case "2008120122": ua_version = "3.0.5"; os_name = oses_windows; break;
			case "2008121623": ua_version = "2.0.0.19"; os_name = oses_linux; os_flavor = "Ubuntu"; break; // browsershots: Firefox 2.0.0.19 / Ubuntu 8.04 LTS (Hardy Heron)
			case "2008121709": ua_version = "2.0.0.20"; os_name = oses_windows; break;
			case "2009011912": ua_version = "3.0.6"; os_name = oses_linux; break;
			case "2009011913": ua_version = "3.0.6"; os_name = oses_windows; break;
			case "2009012615": ua_version = "3.0.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2009012616": ua_version = "3.0.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2009021906": ua_version = "3.0.7"; os_name = oses_linux; break;
			case "2009021910": ua_version = "3.0.7"; os_name = oses_windows; break;
			case "2009030422": ua_version = "3.0.8"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2009032608": ua_version = "3.0.8"; os_name = oses_linux; break;
			case "2009032609": ua_version = "3.0.8"; os_name = oses_windows; break;
			case "2009032711": ua_version = "3.0.9"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2009033100":
				switch (navigator.productSub) {
					case "2009033100": ua_version = "3.0.8"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
					case "2009042113": ua_version = "3.0.9"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "2009040820": ua_version = "3.0.9"; os_name = oses_linux; break;
			case "2009040821": ua_version = "3.0.9"; os_name = oses_windows; break;
			case "2009042113": ua_version = "3.0.10"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2009042114": ua_version = "3.0.10"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "2009042315": ua_version = "3.0.10"; os_name = oses_linux; break;
			case "2009042316": ua_version = "3.0.10"; os_name = oses_windows; break;
			case "20090427153806": ua_version = "3.5.0.b4"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20090427153807": ua_version = "3.5.0.b4"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "2009060214": ua_version = "3.0.11"; os_name = oses_linux; break;
			case "2009060215": ua_version = "3.0.11"; os_name = oses_windows; break;
			case "2009060308":
				switch (navigator.productSub) {
					case "2009060308": ua_version = "3.0.11"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
					case "2009070811": ua_version = "3.0.12"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "2009060309":
				switch (navigator.productSub) {
					case "2009060309": ua_version = "3.0.11"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
					case "2009070811": ua_version = "3.0.12"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
				} break;
			case "2009060310": ua_version = "3.0.11"; os_name = oses_linux; os_flavor = "BackTrack"; break;
			case "2009062005": ua_version = "3.0.11"; os_name = oses_linux; os_flavor = "PCLunixOS"; break;
			case "20090624012136": ua_version = "3.5.0"; os_name = oses_mac_osx; break;
			case "20090624012820": ua_version = "3.5.0"; os_name = oses_linux; break;
			case "20090701234143": ua_version = "3.5.0"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20090702060527": ua_version = "3.5.0"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "2009070610": ua_version = "3.0.12"; os_name = oses_linux; break;
			case "2009070611": ua_version = "3.0.12"; os_name = oses_windows; break;
			case "2009070811": ua_version = "3.0.13"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "20090715083437": ua_version = "3.5.1"; os_name = oses_mac_osx; break;
			case "20090715083816": ua_version = "3.5.1"; os_name = oses_linux; break;
			case "20090715094852": ua_version = "3.5.1"; os_name = oses_windows; break;
			case "2009072202": ua_version = "3.0.12"; os_name = oses_linux; os_flavor = "Oracle"; break;
			case "2009072711": ua_version = "3.0.12"; os_name = oses_linux; os_flavor = "CentOS"; break;
			case "20090729211433": ua_version = "3.5.2"; os_name = oses_mac_osx; break;
			case "20090729211829": ua_version = "3.5.2"; os_name = oses_linux; break;
			case "20090729225027": ua_version = "3.5.2"; os_name = oses_windows; break;
			case "2009073021": ua_version = "3.0.13"; os_name = oses_linux; break;
			case "2009073022": ua_version = "3.0.13"; os_name = oses_windows; break;
			case "20090824085414": ua_version = "3.5.3"; os_name = oses_mac_osx; break;
			case "20090824085743": ua_version = "3.5.3"; os_name = oses_linux; break;
			case "20090824101458": ua_version = "3.5.3"; os_name = oses_windows; break;
			case "2009082707": ua_version = "3.0.14"; break;
			case "2009090216": ua_version = "3.0.14"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20090914014745": ua_version = "3.5.3"; os_name = oses_linux; os_flavor = "Mandriva"; arch = arch_x86; break;
			case "20090915065903": ua_version = "3.5.3"; os_name = oses_linux; os_flavor = "Sabayon"; arch = arch_x86_64; break;
			case "20090915070141": ua_version = "3.5.3"; os_name = oses_linux; os_flavor = "Sabayon"; arch = arch_x86; break;
			case "20091007090112": ua_version = "3.5.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20091007095328": ua_version = "3.5.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "2009101600":
				switch (navigator.productSub) {
					case "2009101600": ua_version = "3.0.15"; break; // Can be either Mac or Linux
					case "20091016": ua_version = "3.5.4"; os_name = oses_linux; os_flavor = "SUSE"; arch = arch_x86; break;
				} break;
			case "2009101601": ua_version = "3.0.15"; os_name = oses_windows; break;
			case "20091016081620": ua_version = "3.5.4"; os_name = oses_mac_osx; break;
			case "20091016081727": ua_version = "3.5.4"; os_name = oses_linux; break;
			case "20091016092926": ua_version = "3.5.4"; os_name = oses_windows; break;
			case "20091020122601": ua_version = "3.5.4"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "2009102814":
				switch (navigator.productSub) {
					case "2009121601": ua_version = "3.0.16"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
					case "2009121602": ua_version = "3.0.16"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
					case "2010010604": ua_version = "3.0.17"; os_name = oses_linux; os_flavor = "Mint"; break;
					case "2010021501": ua_version = "3.0.17;xul1.9.0.18"; os_name = oses_linux; os_flavor = "Mint"; arch = arch_x86; break;
					case "2010021502": ua_version = "3.0.17;xul1.9.0.18"; os_name = oses_linux; os_flavor = "Mint"; arch = arch_x86_64; break;
				} break;
			case "2009102815":
				switch (navigator.productSub) {
					case "2009102815": ua_version = "3.0.15"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
					case "2009121601": ua_version = "3.0.16"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "20091029152254": ua_version = "3.6.0.b1"; os_name = oses_linux; break;
			case "20091029171059": ua_version = "3.6.0.b1"; os_name = oses_windows; break;
			case "20091102134505": ua_version = "3.5.5"; os_name = oses_mac_osx; break;
			case "20091102141836": ua_version = "3.5.5"; os_name = oses_linux; break;
			case "20091102152451": ua_version = "3.5.5"; os_name = oses_windows; break;
			case "2009110421": ua_version = "3.0.15"; os_name = oses_freebsd; arch = arch_x86; break;
			case "20091106091959": ua_version = "3.5.5"; os_name = oses_linux; os_flavor = "Mandriva"; arch = arch_x86; break;
			case "20091106140514": ua_version = "3.5.5"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20091106145609": ua_version = "3.5.5"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "20091108163911": ua_version = "3.6.0.b2"; os_name = oses_linux; break;
			case "20091108181924": ua_version = "3.6.0.b2"; os_name = oses_windows; break;
			case "20091109125225":
				switch (navigator.productSub) {
					case "20091109": ua_version = "3.5.5"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
					case "20091215": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
				} break;
			case "20091109134913": ua_version = "3.5.5"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20091115172547": ua_version = "3.6.0.b3"; os_name = oses_linux; break;
			case "20091115182845": ua_version = "3.6.0.b3"; os_name = oses_windows; break;
			case "20091124201530": ua_version = "3.6.0.b4"; os_name = oses_mac_osx; break;
			case "20091124201751": ua_version = "3.6.0.b4"; os_name = oses_linux; break;
			case "20091124213835": ua_version = "3.6.0.b4"; os_name = oses_windows; break;
			case "2009120100": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "20091201203240": ua_version = "3.5.6"; os_name = oses_mac_osx; break;
			case "20091201204959": ua_version = "3.5.6"; os_name = oses_linux; break;
			case "20091201220228": ua_version = "3.5.6"; os_name = oses_windows; break;
			case "2009120206": ua_version = "3.0.16"; break; // Can be either Mac or Linux
			case "2009120208": ua_version = "3.0.16"; os_name = oses_windows; break;
			case "20091204132459": ua_version = "3.6.0.b5"; os_name = oses_linux; break;
			case "20091204132509": ua_version = "3.6.0.b5"; os_name = oses_mac_osx; break;
			case "20091204143806": ua_version = "3.6.0.b5"; os_name = oses_windows; break;
			case "20091215230859": ua_version = "3.5.7"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20091215230946": ua_version = "3.5.7"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20091215231400": ua_version = "3.5.7"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20091215231754":
				switch (navigator.productSub) {
					case "20091215": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
					case "20100106": ua_version = "3.5.7"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
				} break;
			case "2009121601":
				switch (navigator.productSub) {
					case "2009121601": ua_version = "3.0.16"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
					case "2010010604": ua_version = "3.0.17"; os_name = oses_linux; os_flavor = "Ubuntu"; break; // Could also be Mint x86-64
				} break;
			case "2009121602": ua_version = "3.0.17"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "20091216104148": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "Mandriva"; break;
			case "20091216132458": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20091216132537": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20091216142458": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20091216142519": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "2009121708": ua_version = "3.0.16"; os_name = oses_linux; os_flavor = "CentOS"; arch = arch_x86; break;
			case "20091221151141": ua_version = "3.5.7"; os_name = oses_mac_osx; break;
			case "20091221152502": ua_version = "3.5.7"; os_name = oses_linux; break;
			case "2009122115": ua_version = "3.0.17"; break; // Can be either Mac or Linux
			case "20091221164558": ua_version = "3.5.7"; os_name = oses_windows; break;
			case "2009122116": ua_version = "3.0.17"; os_name = oses_windows; break;
			case "2009122200": ua_version = "3.5.7"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "20091223231431": ua_version = "3.5.6"; os_name = oses_linux; os_flavor = "PCLunixOS"; arch = arch_x86; break;
			case "20100105194006": ua_version = "3.6.0.rc1"; os_name = oses_mac_osx; break;
			case "20100105194116": ua_version = "3.6.0.rc1"; os_name = oses_linux; break;
			case "20100105212446": ua_version = "3.6.0.rc1"; os_name = oses_windows; break;
			case "2010010604": ua_version = "3.0.18"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "20100106054534": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20100106054634": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "2010010605": ua_version = "3.0.18"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100106211825": ua_version = "3.5.7"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20100106212742": ua_version = "3.5.7"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100106215614": ua_version = "3.5.7"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20100110112429": ua_version = "3.5.7"; os_name = oses_linux; os_flavor = "Mandriva"; break;
			case "20100115132715": ua_version = "3.6.0"; os_name = oses_mac_osx; break;
			case "20100115133306": ua_version = "3.6.0"; os_name = oses_linux; break;
			case "20100115144158": ua_version = "3.6.0"; os_name = oses_windows; break;
			case "20100125074043": ua_version = "3.6.0"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break; // Could also be Mint x86
			case "20100125074127": ua_version = "3.6.0"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "20100125204847": ua_version = "3.6.0"; os_name = oses_linux; os_flavor = "Sabayon"; arch = arch_x86; break; // Could also be Mint x86
			case "20100125204903": ua_version = "3.6.0"; os_name = oses_linux; os_flavor = "Sabayon"; arch = arch_x86_64; break; // Could also be Mint x86-64
			case "20100202152834": ua_version = "3.5.8"; os_name = oses_mac_osx; break;
			case "20100202153512": ua_version = "3.5.8"; os_name = oses_linux; break;
			case "20100202165920": ua_version = "3.5.8"; os_name = oses_windows; break;
			case "2010020219": ua_version = "3.0.18"; os_name = oses_mac_osx; break;
			case "2010020220": ua_version = "3.0.18"; os_name = oses_windows; break;
			case "2010020400": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "20100212131909": ua_version = "3.6.0.2"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100212132013": ua_version = "3.6.0.2"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100216105329": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20100216105348": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100216105410": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100216110009": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "2010021718": ua_version = "3.0.18"; os_name = oses_linux; os_flavor = "CentOS"; arch = arch_x86; break;
			case "20100218022359": ua_version = "3.6.0.4"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100218022705": ua_version = "3.6.0.4"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100218112915": ua_version = "3.5.8"; os_name = oses_linux; os_flavor = "Mandriva"; arch = arch_x86; break;
			case "20100222120605": ua_version = "3.6.0.5"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100222120717": ua_version = "3.6.0.5"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100301015346": ua_version = "3.6.0"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20100305054927": ua_version = "3.6.0"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100307204001": ua_version = "3.6.0"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20100308142847": ua_version = "3.6.0.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100308151019": ua_version = "3.6.0.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "2010031218": ua_version = "3.0.19"; break; // Mac OS X or Linux
			case "2010031422": ua_version = "3.0.19"; os_name = oses_windows; break;
			case "20100315075757": ua_version = "3.5.9"; os_name = oses_linux; break;
			case "20100315080228": ua_version = "3.5.9"; os_name = oses_mac_osx; break;
			case "20100315083431": ua_version = "3.5.9"; os_name = oses_windows; break;
			case "20100316055951": ua_version = "3.6.2"; os_name = oses_mac_osx; break;
			case "20100316060223": ua_version = "3.6.2"; os_name = oses_linux; break;
			case "20100316074819": ua_version = "3.6.2"; os_name = oses_windows; break;
			case "2010031700": ua_version = "3.5.9"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "20100323102218": ua_version = "3.6.2"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20100323102339": ua_version = "3.6.2"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100323194640": ua_version = "3.6.2"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100324182054": ua_version = "3.6.2"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20100330071911": ua_version = "3.5.9"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20100330072017": ua_version = "3.5.9"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20100330072020": ua_version = "3.5.9"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100330072034": ua_version = "3.5.9"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100401064631": ua_version = "3.6.3"; os_name = oses_mac_osx; break;
			case "20100401074458": ua_version = "3.6.3"; os_name = oses_linux; break;
			case "20100401080539": ua_version = "3.6.3"; os_name = oses_windows; break;
			case "20100401144201": ua_version = "3.6.2"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2010040116": ua_version = "3.0.19"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2010040118": ua_version = "3.0.19"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2010040119": ua_version = "3.0.19"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100401213457": ua_version = "3.5.9"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "2010040121": ua_version = "3.0.19"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "2010040123": ua_version = "3.0.19"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "2010040200": ua_version = "3.0.19"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100402010516": ua_version = "3.5.9"; os_name = oses_linux; os_flavor = "Mint"; arch = arch_x86_64; break;
			case "20100402041908": ua_version = "3.6.2"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100403042003": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20100403082016": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100404024515": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100404024646": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100404104043": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "PClinuxOS"; arch = arch_x86_64; break;
			case "20100409151117": ua_version = "3.6.3.2"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100409170726": ua_version = "3.6.3.2"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100412125148": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Mandriva"; arch = arch_x86; break;
			case "20100413152922": ua_version = "3.6.4.b1"; os_name = oses_mac_osx; break;
			case "20100413154310": ua_version = "3.6.4.b1"; os_name = oses_linux; break;
			case "20100413172113": ua_version = "3.6.4.b1"; os_name = oses_windows; break;
			case "20100415062243": ua_version = "3.6.3.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100415103754": ua_version = "3.6.3.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100416101101": ua_version = "3.6.3.2"; os_name = oses_linux; os_flavor = "Mandriva"; arch = arch_x86; break;
			case "2010041700": ua_version = "3.6.4.1"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "20100419015333": ua_version = "3.6.3"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100423043606": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Sabayon"; arch = arch_x86_64; break;
			case "20100423140709": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100423141150": ua_version = "3.6.3"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100423142835": ua_version = "3.6.3"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20100502202326": ua_version = "3.6.4.b2"; os_name = oses_linux; break;
			case "20100502202401": ua_version = "3.6.4.b2"; os_name = oses_mac_osx; break;
			case "20100502221517": ua_version = "3.6.4.b2"; os_name = oses_windows; break;
			case "20100503113315": ua_version = "3.6.4.b3"; os_name = oses_mac_osx; break;
			case "20100503113541": ua_version = "3.6.4.b3"; os_name = oses_linux; break;
			case "20100503122926": ua_version = "3.6.4.b3"; os_name = oses_windows; break;
			case "20100504085637": ua_version = "3.5.10"; os_name = oses_linux; break;
			case "20100504085753": ua_version = "3.5.10"; os_name = oses_mac_osx; break;
			case "20100504093643": ua_version = "3.5.10"; os_name = oses_windows; break;
			case "2010050600": ua_version = "3.5.10"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "2010051300": ua_version = "3.6.4.1"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "20100513134853": ua_version = "3.6.4.b4"; os_name = oses_mac_osx; break;
			case "20100513140540": ua_version = "3.6.4.b4"; os_name = oses_linux; break;
			case "20100513144105": ua_version = "3.6.4.b4"; os_name = oses_windows; break;
			case "20100513190740": ua_version = "3.6.3"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100523180910": ua_version = "3.6.4.b5"; os_name = oses_mac_osx; break;
			case "20100523181754": ua_version = "3.6.4.b5"; os_name = oses_linux; break;
			case "20100523185824": ua_version = "3.6.4.b5"; os_name = oses_windows; break;
			case "20100527084110": ua_version = "3.6.4.b6"; os_name = oses_mac_osx; break;
			case "20100527085242": ua_version = "3.6.4.b6"; os_name = oses_linux; break;
			case "20100527093236": ua_version = "3.6.4.b6"; os_name = oses_windows; break;
			case "2010061100": ua_version = "3.6.4"; os_name = oses_linux; os_flavor = "SUSE"; break;
			case "20100611134546": ua_version = "3.6.4.b7"; os_name = oses_mac_osx; break;
			case "20100611135942": ua_version = "3.6.4.b7"; os_name = oses_linux; break;
			case "20100611143157": ua_version = "3.6.4.b7"; os_name = oses_windows; break;
			case "20100622203044": ua_version = "3.6.4"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20100622203045": ua_version = "3.6.4"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100622204750": ua_version = "3.5.10"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86_64; break;
			case "20100622204830": ua_version = "3.5.10"; os_name = oses_linux; os_flavor = "Fedora"; arch = arch_x86; break;
			case "20100622205038": ua_version = "3.6.4"; os_name = oses_linux; os_flavor = "PClinuxOS"; arch = arch_x86_64; break;
			case "20100623081410": ua_version = "3.6.4"; os_name = oses_linux; os_flavor = "CentOS"; arch = arch_x86_64; break;
			case "20100623081921": ua_version = "3.6.4"; os_name = oses_linux; os_flavor = "CentOS"; arch = arch_x86; break;
			case "20100623155731": ua_version = "3.6.4.b7"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100623200132": ua_version = "3.6.4.b7"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100625222733": ua_version = "3.6.6"; os_name = oses_linux; break;
			case "20100625223402": ua_version = "3.6.6"; os_name = oses_mac_osx; break;
			case "20100625231939": ua_version = "3.6.6"; os_name = oses_windows; break;
			case "20100626104508": ua_version = "3.6.4"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86; break;
			case "20100627211341": ua_version = "3.6.4"; os_name = oses_freebsd; os_flavor = "PC-BSD"; arch = arch_x86_64; break;
			case "20100628082832": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "PClinuxOS"; arch = arch_x86_64; break;
			case "20100628124739": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100628143222": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100628232431": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100629034705": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100629105354": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Mandriva"; arch = arch_x86; break;
			case "20100630130433": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100630131607": ua_version = "4.0.0.b1"; os_name = oses_mac_osx; break;
			case "20100630132217": ua_version = "4.0.0.b1"; os_name = oses_linux; break;
			case "20100630141702": ua_version = "4.0.0.b1"; os_name = oses_windows; break;
			case "20100630174226": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Sabayon"; arch = arch_x86_64; break;
			case "20100630180611": ua_version = "3.6.6"; os_name = oses_linux; os_flavor = "Sabayon"; arch = arch_x86; break;
			case "20100709115208": ua_version = "3.6.7.b1"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86; break;
			case "20100709183408": ua_version = "3.6.7.b1"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20100716093011": ua_version = "3.6.7.b2"; os_name = oses_linux; os_flavor = "Ubuntu"; arch = arch_x86_64; break;
			case "20101203075014": ua_version = "3.6.13"; os_name = oses_windows; break;
			case "20101206122825": ua_version = "3.6.13"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "20110318052756": ua_version = "4.0"; os_name = oses_windows; break; // browsershots: Firefox 4.0 / Windows XP
			case "20110420144310": ua_version = "3.5.19"; os_name = oses_linux; os_flavor = "Debian"; break; // browsershots: Firefox 3.5.19 / Debian 4.0 (Etch)
			case "20110615151330": ua_version = "5.0"; os_name = oses_windows; break; // browsershots: Firefox 5.0 / Windows XP
			case "20110811165603": ua_version = "6.0"; os_name = oses_windows; break; // browsershots: Firefox 6.0 / Windows XP
			case "20110830092941": ua_version = "6.0.1"; os_name = oses_linux; os_flavor = "Debian"; break; // browsershots: Firefox 6.0.1 / Debian 4.0 (Etch)
			case "20110922153450": ua_version = "7.0"; os_name = oses_windows; break; // browsershots: Firefox 7.0 / Windows XP
			case "20110928134238": ua_version = "7.0.1"; os_name = oses_linux; os_flavor = "Debian"; break; // browsershots: Firefox 7.0.1 / Debian 4.0 (Etch)
			case "20111104165243": ua_version = "8.0"; os_name = oses_windows; break; // browsershots: Firefox 8.0 / Windows XP
			case "20111115183813": ua_version = "8.0"; os_name = oses_linux; os_flavor = "Ubuntu"; break; // browsershots: Firefox 8.0 / Ubuntu 9.10 (Karmic Koala)
			case "20111216140209": ua_version = "9.0"; os_name = oses_windows; break; // browsershots: Firefox 9.0 / Windows XP
			case "20120129021758": ua_version = "10.0"; os_name = oses_windows; break; // browsershots: Firefox 10.0 / Windows 2000
			case "20120201083324": ua_version = "3.5.16"; os_name = oses_linux; os_flavor = "Debian"; break; // browsershots: Iceweasel 3.5.16 / Debian 4.0 (Etch)
			case "20120216013254": ua_version = "3.6.27"; os_name = oses_linux; os_flavor = "Debian"; break; // browsershots: Firefox 3.6.27 / Debian 4.0 (Etch)
			case "20120216100510": ua_version = "10.0.2"; os_name = oses_linux; os_flavor = "Ubuntu"; break; // browsershots: Firefox 10.0.2 / Ubuntu 9.10 (Karmic Koala)
			case "20120310010316": ua_version = "11.0"; os_name = oses_linux; os_flavor = "Ubuntu"; break; // browsershots: Firefox 11.0 / Ubuntu 9.10 (Karmic Koala)
			case "20120310194926": ua_version = "11.0"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "20120312181643":
				// It is disconcerting that a buildID is the same on Windows
				// and Mac, need to examine more versions on Mac.
				ua_version = "11.0";
				if (/Mac/.test(navigator.oscpu)) {
					os_name = oses_mac_osx;
				} else {
					os_name = oses_windows; // browsershots: Firefox 11.0 / Windows XP
				}
				break;
			case "20120314195616": ua_version = "12.0"; os_name = oses_linux; os_flavor = "Debian"; break; // browsershots: Firefox 12.0 / Debian 4.0 (Etch)
			case "20120423142301": ua_version = "12.0"; os_name = oses_linux; os_flavor = "Ubuntu"; break;
			case "20120424151700": ua_version = "12.0"; os_name = oses_linux; os_flavor = "Fedora"; break;
			default:
				version = this.searchVersion("Firefox", navigator.userAgent);
				// Verify whether the ua string is lying by checking if it contains
				// the major version we detected using known objects above.  If it
				// appears to be truthful, then use its more precise version number.
				if (version && version.split(".")[0] == ua_version.split(".")[0]) {
					// The version number will sometimes end with a space or end of
					// line, so strip off anything after a space if one exists
					if (-1 != version.indexOf(" ")) {
						version = version.substr(0,version.indexOf(" "));
					}
					ua_version = version;
				} else {
					ua_is_lying = true;
				}
				break;
		}
		//if (ua_is_lying) { alert("UA is lying"); }
		//alert(ua_version + " vs " + navigator.userAgent);

		// end navigator.buildID checks

	} else if (typeof ScriptEngineMajorVersion == "function") {
		// Then this is IE and we can very reliably detect the OS.
		// Need to add detection for IE on Mac.  Low priority, since we
		// don't have any sploits for it yet and it's a very low market
		// share.
		os_name = oses_windows;
		ua_name = clients_ie;
		version = ScriptEngineMajorVersion().toString();
		version += ScriptEngineMinorVersion().toString();
		version += ScriptEngineBuildVersion().toString();
		//document.write("ScriptEngine: "+version+"<br />");
		switch (version){
			case "514615":
				// IE 5.00.2920.0000, 2000 Advanced Server SP0 English
				ua_version = "5.0";
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
				// IE 6.0.2800.1106, XP SP1 English
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
			case "568820":
				// IE 6.0.2900.2180, xp sp2 english
				os_flavor = "XP";
				os_sp = "SP2";
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
			case "568837":
				// IE 6.0.2900.2180, XP Professional SP2 Korean
				ua_version = "6.0";
				os_flavor = "XP";
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
				os_flavor = "XP";
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
				os_flavor = "XP";
				os_sp = "SP3";
				break;
			case "5722589":
				// IE 7.0.5730.13, XP Professional SP3 English
				ua_version = "7.0";
				os_flavor = "XP";
				os_sp = "SP3";
				break;
			case "576000":
				// IE 7.0.6000.16386, Vista Ultimate SP0 English
				ua_version = "7.0";
				os_flavor = "Vista";
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
				os_flavor = "7";
				os_sp = "SP0";
				break;
			case "5817514":
				// IE 8.0.7600.17514, Windows 7 SP1 English
				ua_version = "8.0";
				os_flavor = "7";
				os_sp = "SP1";
				break;
			case "5818702":
				// IE 8.0.6001.18702, XP Professional SP3 English
			case "5822960":
				// IE 8.0.6001.18702, XP Professional SP3 Greek
				ua_version = "8.0";
				os_flavor = "XP";
				os_sp = "SP3";
				break;
			case "9016406":
				// IE 9.0.7930.16406, Windows 7 64-bit
				ua_version = "9.0";
				os_flavor = "7";
				os_sp = "SP0";
				break;
			case "9016441":
				// IE 9.0.8112.16421, Windows 7 32-bit English
				ua_version = "9.0";
				os_flavor = "7";
				os_sp = "SP1";
				break;
			case "9016443":
				// IE 9.0.8112.16421, Windows 7 Polish
				// Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)
				ua_version = "9.0";
				os_flavor = "7";
				os_sp = "SP1";
				break;
			case "9016446":
				// IE 9.0.8112.16421, Windows 7 English (Update Versions: 9.0.7 (KB2699988)
				// Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; MASA; InfoPath.3; MS-RTC LM 8; BRI/2)Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; MASA; InfoPath.3; MS-RTC LM 8; BRI/2)
				ua_version = "9.0";
				os_flavor = "7";
				os_sp = "SP1";
				break;
			case "9016464":
				// browsershots.org, MSIE 7.0 / Windows 2008 R2
				os_flavor = "2008R2";
				ua_version = "9.0";
				break;
			case "9016470":
				// IE 9.0.8112.16421 / Windows 7 SP1
				ua_version = "9.0";
				os_flavor = "7";
				os_sp = "SP1";
				break;
			case "1000":
				// IE 10.0.8400.0 (Pre-release + KB2702844), Windows 8 x86 English Pre-release
				ua_version = "10.0";
				os_flavor = "8";
				os_sp = "SP0";
				break;
			default:
				unknown_fingerprint = version;
				break;
		}

		if (!ua_version) {
			// The ScriptEngine functions failed us, try some object detection
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

	if (!os_name && navigator.platform == "Win32") { os_name = oses_windows; }

	//--
	// Flavor
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
	if (os_name == oses_windows && (!os_flavor || 0 == os_flavor.length)) {
		if (version.indexOf("windows 95") != -1)          { os_flavor = "95";    }
		else if (version.indexOf("windows nt 4") != -1)   { os_flavor = "NT";    }
		else if (version.indexOf("win 9x 4.9") != -1)     { os_flavor = "ME";    }
		else if (version.indexOf("windows 98") != -1)     { os_flavor = "98";    }
		else if (version.indexOf("windows nt 5.0") != -1) { os_flavor = "2000";  }
		else if (version.indexOf("windows nt 5.1") != -1) { os_flavor = "XP";    }
		else if (version.indexOf("windows nt 5.2") != -1) { os_flavor = "2003";  }
		else if (version.indexOf("windows nt 6.0") != -1) { os_flavor = "Vista"; }
		else if (version.indexOf("windows nt 6.1") != -1) { os_flavor = "7";     }
		else if (version.indexOf("windows nt 6.2") != -1) { os_flavor = "8";     }
	}
	if (os_name == oses_linux && (!os_flavor || 0 == os_flavor.length)) {
		if (version.indexOf("gentoo") != -1)       { os_flavor = "Gentoo";  }
		else if (version.indexOf("ubuntu") != -1)  { os_flavor = "Ubuntu";  }
		else if (version.indexOf("debian") != -1)  { os_flavor = "Debian";  }
		else if (version.indexOf("rhel") != -1)    { os_flavor = "RHEL";    }
		else if (version.indexOf("red hat") != -1) { os_flavor = "RHEL";    }
		else if (version.indexOf("centos") != -1)  { os_flavor = "CentOS";  }
		else if (version.indexOf("fedora") != -1)  { os_flavor = "Fedora";  }
		else if (version.indexOf("android") != -1) { os_flavor = "Android"; }
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
	this.os_flavor = os_flavor;
	this.os_sp = os_sp;
	this.os_lang = os_lang;
	this.arch = arch;
	this.ua_name = ua_name;
	this.ua_version = ua_version;
	this.ua_version = ua_version;

	return { os_name:os_name, os_flavor:os_flavor, os_sp:os_sp, os_lang:os_lang, arch:arch, ua_name:ua_name, ua_version:ua_version };
}; // function getVersion

window.os_detect.searchVersion = function(needle, haystack) {
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
window.ua_ver_cmp = function(ver_a, ver_b) {
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

window.ua_ver_lt = function(a, b) {
	if (-1 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
window.ua_ver_gt = function(a, b) {
	if (1 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
window.ua_ver_eq = function(a, b) {
	if (0 == this.ua_ver_cmp(a,b)) { return true; }
	return false;
};
