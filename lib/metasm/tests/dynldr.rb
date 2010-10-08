#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'test/unit'
require 'metasm'

class TestDynldr < Test::Unit::TestCase

	def test_dynldr
		str = "1234"
		d = Metasm::DynLdr
		d.new_api_c('int memcpy(char*, char*, int)')
		d.memcpy(str, "9999", 2)
		assert_equal('9934', str)

		c_src = <<EOS
int sprintf(char*, char*, ...);
void fufu(int i, char* ptr)
{
	sprintf(ptr, "lolzor %i\\n", i);
}
EOS
		buf = 'aaaaaaaaaaaaaaaaaa'
		d.new_func_c(c_src) { d.fufu(42, buf) }
		assert_equal("lolzor 42\n\000aaaaaaa", buf)
	end
end
