package 
{
	import flash.utils.ByteArray;
	
	public class PE32  
	{
		private var m:Memory;
		
		public var base:uint;
		public var dos_header:uint;
		public var nt_header:uint;
		public var file_header:uint;
		public var opt_header:uint;
		
		private function FindBase(ptr:uint):uint {
			ptr = ptr & 0xffff0000;
			var dword:uint = m.read_dword(ptr);

			while ((dword & 0xffff) != 0x5a4d) {
				ptr -= 0x10000;
				dword = m.read_dword(ptr);
			}
			
			return ptr;
		}
		
		public function ParseHeaders():void {
			dos_header = base;
			var e_lfanew:uint = m.read_dword(dos_header + 60);
			
			nt_header = dos_header + e_lfanew;
			var nt_magic:uint = m.read_dword(nt_header);
			if (nt_magic != 0x00004550) {
				dos_header = 0;
				nt_header = 0;
				return;
			}
			
			file_header = nt_header + 4;
			var machine:uint = m.read_dword(file_header);
			if ((machine & 0xffff) != 0x014c) {
				dos_header = 0;
				nt_header = 0;
				file_header = 0;
				return;
			}
			
			opt_header = nt_header + 24;
			var opt_magic:uint = m.read_dword(opt_header);
			if ((opt_magic & 0xffff) != 0x10b) {
				dos_header = 0;
				nt_header = 0;
				file_header = 0;
				opt_header = 0;
				return;
			}
		}
		
		public function GetImport(mod_name:String, fun_name:String):uint {
			if (base == 0 || dos_header == 0) {
				return 0;
			}
			
			var data_directory:uint = opt_header + 96;
			
			var import_dir:uint = data_directory + 8;
			var import_rva:uint = m.read_dword(import_dir);
			var import_size:uint = m.read_dword(import_dir + 4);	  
			if (import_size == 0) {
				return 0;
			}
			
			var import_descriptor:uint = base + import_rva;
			var orig_first_thunk:uint = m.read_dword(import_descriptor);
			while (orig_first_thunk != 0) {
			
				var module_name_ptr:uint = 
					dos_header + m.read_dword(import_descriptor + 12);
				
				if (module_name_ptr != 0) {
					var module_name:String = m.read_string(module_name_ptr);
					if (module_name == mod_name) {
						orig_first_thunk += dos_header;
						break;
					}
				}
				
				import_descriptor += (5 * 4);
				orig_first_thunk = m.read_dword(import_descriptor);
			}
			
			var first_thunk:uint = dos_header + m.read_dword(import_descriptor + 16);
			var thunk:uint = orig_first_thunk;
			var import_by_name_rva:uint = m.read_dword(thunk);
			while (import_by_name_rva != 0) {
				var function_name_ptr:uint = dos_header + import_by_name_rva + 2;
				
				var function_name:String = m.read_string(function_name_ptr);
				if (function_name == fun_name) {
					return m.read_dword(first_thunk);
				}
				
				thunk += 4;
				first_thunk += 4;
				import_by_name_rva = m.read_dword(thunk);
			}
			
			return 0;
		}
		
		public function GetGadget(gadget:ByteArray):uint {
			var opt_header_size:uint = m.read_dword(file_header + 16) & 0xffff;
			var section_count:uint = (m.read_dword(file_header) >> 16) & 0xffff;
			var section_header:uint = opt_header + opt_header_size;
			
			for (var i:uint = 0; i < section_count; ++i) {
				var characteristics:uint = m.read_dword(section_header + (9 * 4));
				
				if ((characteristics & 0xe0000000) == 0x60000000) {
					// this section is read/execute, so scan for gadget
					
					var section_rva:uint = m.read_dword(section_header + 12);
					var section_size:uint = m.read_dword(section_header + 16);
					var section_base:uint = base + section_rva;
					var section:ByteArray = new ByteArray();
					section.endian = "littleEndian";
					section.length = section_size;
					
					for (var j:uint = 0; j < section_size; j += 4) {
						section.writeUnsignedInt(
							m.read_dword(section_base + j));
					}
					
					for (j = 0; j < section_size; j += 1) {
						section.position = j;
						gadget.position = 0;					
						while (section.readByte() == gadget.readByte()) {
							if (gadget.position == gadget.length) {
								return section_base + j;
							}
						}
					}
				}
				
				section_header += 10 * 5;
			}
			
			return 0;
		}
		
		public function PE32(memory:Memory, ptr:uint) {
			m = memory;
			base = FindBase(ptr);
			ParseHeaders();
		}
	}	
}