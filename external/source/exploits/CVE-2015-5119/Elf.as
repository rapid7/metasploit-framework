package
{
    public class Elf
    {
        private const PT_DYNAMIC:uint = 2
        private const PT_LOAD:uint = 1 
        private const PT_READ_EXEC:uint = 5
        private const DT_SYMTAB:uint = 6
        private const DT_STRTAB:uint = 5
        private const DT_PLTGOT:uint = 3

        private var e_ba:ExploitByteArray
        // elf base address
        public var base:uint = 0
        // program header address
        public var ph:uint = 0
        // number of program headers
        public var ph_size:uint = 0
        // program header entry size
        public var ph_esize:uint = 0
        // DYNAMIC segment address
        public var seg_dynamic:uint = 0
        // DYNAMIC segment size
        public var seg_dynamic_size:uint = 0
        // CODE segment address
        public var seg_exec:uint = 0
        // CODE segment size
        public var seg_exec_size:uint = 0
        // .dynsyn section address
        public var sec_dynsym:uint = 0
        // .synstr section address
        public var sec_dynstr:uint = 0
        // .got.plt section address
        public var sec_got_plt:uint = 0
         
        public function Elf(ba:ExploitByteArray, addr:uint) 
        {
            e_ba = ba
            set_base(addr)
            set_program_header()
            set_program_header_size()
            set_program_header_entry_size()
            set_dynamic_segment()
            set_exec_segment()
            set_dynsym()
            set_dynstr()
            set_got_plt()
        }

        public function external_symbol(name:String):uint {
            var entry:uint = 0
            var st_name:uint = 0
            var st_value:uint = 0
            var st_size:uint = 0
            var st_info:uint = 0
            var st_other:uint = 0
            var st_shndx:uint = 0
            var st_string:String = ""
            var got_plt_index:uint = 0

            for(var i:uint = 0; i < 1000; i++) { // 1000 is just a limit
                entry = sec_dynsym + 0x10 + (i * 0x10)
                st_name = e_ba.read(entry)
                st_value = e_ba.read(entry + 4)
                st_info = e_ba.read(entry + 0xc, "byte")
                st_string = e_ba.read_string(sec_dynstr + st_name)
                if (st_string == name) {
                    return e_ba.read(sec_got_plt + 0xc + (got_plt_index * 4))
                }
                if (st_info != 0x11) {
                    got_plt_index++
                }
            }
            throw new Error()  
        }

        public function symbol(name:String):uint {           
            var entry:uint = 0
            var st_name:uint = 0
            var st_value:uint = 0
            var st_size:uint = 0
            var st_info:uint = 0
            var st_other:uint = 0
            var st_shndx:uint = 0
            var st_string:String = ""

            for(var i:uint = 0; i < 3000; i++) { // 3000 is just a limit
                entry = sec_dynsym + 0x10 + (i * 0x10)
                st_name = e_ba.read(entry)
                st_value = e_ba.read(entry + 4)
                st_info = e_ba.read(entry + 0xc, "byte")
                st_string = e_ba.read_string(sec_dynstr + st_name)
                if (st_string == name) {
                    return base + st_value
                }
            }
            throw new Error()  
        }


        public function gadget(gadget:String, hint:uint):uint
        {
            var value:uint = parseInt(gadget, 16)
            var contents:uint = 0
            for (var i:uint = 0; i < seg_exec_size - 4; i++) {
                contents = e_ba.read(seg_exec + i)
                if (hint == 0xffffffff && value == contents) {
                    return seg_exec + i
                } 
                if (hint != 0xffffffff && value == (contents & hint)) { 
                    return seg_exec + i
                }
            }
            throw new Error()
        } 
 
        private function set_base(addr:uint):void
        {
            addr &= 0xffff0000
            while (true) {
                if (e_ba.read(addr) == 0x464c457f) {
                    base = addr
                    return
                }
                addr -= 0x1000
            }
            
            throw new Error()
        }  
 
        private function set_program_header():void
        {
            ph = base + e_ba.read(base + 0x1c)
        }
    
        private function set_program_header_size():void
        {
            ph_size = e_ba.read(base + 0x2c, "word")
        } 

        private function set_program_header_entry_size():void
        {
            ph_esize = e_ba.read(base + 0x2a, "word")
        }
    
        private function set_dynamic_segment():void
        {
            var entry:uint = 0
            var p_type:uint = 0

            for (var i:uint = 0; i < ph_size; i++) {
                entry = ph + (i * ph_esize)
                p_type = e_ba.read(entry)
                if (p_type == PT_DYNAMIC) {
                    seg_dynamic = base + e_ba.read(entry + 8)
                    seg_dynamic_size = e_ba.read(entry + 0x14)
                    return
                }
            }

            throw new Error()
        }

        private function set_exec_segment():void
        {
            var entry:uint = 0
            var p_type:uint = 0
            var p_flags:uint = 0
            
            for (var i:uint = 0; i < ph_size; i++) {
                entry = ph + (i * ph_esize)
                p_type = e_ba.read(entry)
                p_flags = e_ba.read(entry + 0x18)
                if (p_type == PT_LOAD && (p_flags & PT_READ_EXEC) == PT_READ_EXEC) {
                    seg_exec = base + e_ba.read(entry + 8)
                    seg_exec_size = e_ba.read(entry + 0x14)
                    return
                }
            }
            
            throw new Error()
        }
 
        private function set_dynsym():void
        {
            var entry:uint = 0
            var s_type:uint = 0

            for (var i:uint = 0; i < seg_dynamic_size; i = i + 8) {
                entry = seg_dynamic + i
                s_type = e_ba.read(entry)
                if (s_type == DT_SYMTAB) {
                    sec_dynsym = e_ba.read(entry + 4)
                    return
                }
            }
            
            throw new Error()
        }

        private function set_dynstr():void
        {
            var entry:uint = 0
            var s_type:uint = 0

            for (var i:uint = 0; i < seg_dynamic_size; i = i + 8) {
                entry = seg_dynamic + i
                s_type = e_ba.read(entry)
                if (s_type == DT_STRTAB) {
                    sec_dynstr = e_ba.read(entry + 4)
                    return
                }
            }
            
            throw new Error()
        }

        private function set_got_plt():void
        {
            var entry:uint = 0
            var s_type:uint = 0

            for (var i:uint = 0; i < seg_dynamic_size; i = i + 8) {
                entry = seg_dynamic + i
                s_type = e_ba.read(entry)
                if (s_type == DT_PLTGOT) {
                    sec_got_plt = e_ba.read(entry + 4)
                    return
                }
            }
            
            throw new Error()
        }
    }
}
