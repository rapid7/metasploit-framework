package 
{
	// some utilities to encapsulate using the relative read/write of the
	// corrupt vector.<uint> as an absolute read/write of the whole address 
	// space.
	public class Memory
	{
		public var vector:Vector.<uint>;
		public var vector_base:uint;
		public var vector_size:uint;
		
		private static function negative(i:uint):uint {
			return (~i) + 1;
		}
		
		public function Memory(v:Vector.<uint>, b:uint, s:uint) {
			vector = v;
			vector_base = b;
			vector_size = s;
		}
		
		public function Cleanup():void {
			
			// restore the correct size to our vector so that flash doesn't 
			// inadvertently trample on lots of memory.
			
			vector[negative(2)] = vector_size;
		}
		
		public function read_dword(address:uint):uint {
			var offset:uint = 0;
			
			if (address & 0x3 != 0) {
				
				// NB: we could read 2 dwords here, and produce the correct
				// dword, but that could lead to oob reads if we're close to
				// a page boundary. take the path of least danger, and throw
				// for debugging. 
				
				throw 'read_dword called with misaligned address'
			}
			
			if (address < vector_base) {
				offset = negative((vector_base - address) >> 2);
			}
			else {
				offset = address - vector_base >> 2;
			}
			
			try {
				return vector[offset];
			} catch (e:Error) {
				
				// we can't read at offset 0xffffffff, sometimes we will want
				// to, but that is just life.
			}
			
			return 0;
		}
		
		public function read_byte(address:uint):uint {
			var dword_address:uint = address & 0xfffffffc;
			var dword:uint = read_dword(dword_address);
			
			while (address & 0x3) {
				dword = dword >> 8;
				address -= 1;
			}
			
			return (dword & 0xff);
		}
		
		public function read_string(address:uint):String {
			var string:String = '';
			var dword:uint = 0;
			
			while (address & 0x3) {
				var char:uint = read_byte(address);
				
				if (char == 0) {
					return string;
				}
				
				string += String.fromCharCode(char);
				address += 1;
			}
			
			while (true) {
				dword = read_dword(address);
				if ((dword & 0xff) != 0) {
					string += String.fromCharCode(dword & 0xff);
					dword = dword >> 8;
				}
				else {
					return string;
				}
				
				if ((dword & 0xff) != 0) {
					string += String.fromCharCode(dword & 0xff);
					dword = dword >> 8;
				}
				else {
					return string;
				}
				
				if ((dword & 0xff) != 0) {
					string += String.fromCharCode(dword & 0xff);
					dword = dword >> 8;
				}
				else {
					return string;
				}
				
				if ((dword & 0xff) != 0) {
					string += String.fromCharCode(dword & 0xff);
				}
				else {
					return string;
				}
				
				address += 4;
			}
			
			return string;
		}
		
		public function write_dword(address:uint, value:uint):void {
			var offset:uint = 0;
			
			if (address & 0x3 != 0) {
				
				// NB: we could read 2 dwords here, and write 2 dwords, and
				// produce the correct dword, but that could lead to oob reads
				// and writes if we're close to a page boundary. take the path
				// of least danger, and throw for debugging. 
				
				throw 'write_dword called with misaligned address'
			}
			
			if (address < vector_base) {
				offset = negative((vector_base - address) >> 2);
			}
			else {
				offset = (address - vector_base) >> 2;
			}
			
			vector[offset] = value;
		}
	}	
}