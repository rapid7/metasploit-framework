#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: scan for xrefs to the target address, incl. relative offsets (eg near call/jmp)
def scanxrefs(target)
	ans = []
	sections.sort.each { |s_addr, edata|
		raw = edata.data.to_str
		(0..raw.length-4).each { |off|
			r = raw[off, 4].unpack('V').first
			ans << (s_addr + off) if (r + off+4 + s_addr)&0xffffffff == target or r == target
		}
	}
	ans
end

gui.keyboard_callback[?X] = lambda {
	target = gui.curaddr
	ans = scanxrefs(target)
	list = [['addr']] + ans.map { |off| [Expression[off].to_s] }
	gui.listwindow("scanned xrefs to #{Expression[target]}", list) { |i| gui.focus_addr i[0] }
	true
} if gui
