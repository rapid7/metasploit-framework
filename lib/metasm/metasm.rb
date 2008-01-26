#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# temporarily put the current file directory in the ruby include path
metasmdir = File.dirname(__FILE__)
if $:.include? metasmdir
	metasmdir = nil
else
	$: << metasmdir
end

# cpu architectures
%w[ia32 mips].each { |f|
	require "metasm/#{f}/render"
	require "metasm/#{f}/parse"
	require "metasm/#{f}/encode"
	require "metasm/#{f}/decode"
	require "metasm/#{f}/compile_c"
}
# executable formats
%w[mz elf_encode elf_decode pe coff_encode coff_decode shellcode a_out xcoff autoexe].each { |f|
	require "metasm/exe_format/#{f}"
}
# os-specific features
%w[windows linux].each { |f|
	require "metasm/os/#{f}"
}

require 'metasm/parse_c'
require 'metasm/compile_c'

# cleanup include path
$:.delete metasmdir if metasmdir
