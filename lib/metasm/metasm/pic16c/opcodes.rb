#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/pic16c/main'

module Metasm
class Pic16c
	def addop(name, bin, *l)
		o = Opcode.new name, bin
		l.each { |ll|
			if @props_allowed[ll]
				o.props[ll] = true
			else
				o.args << ll
				o.fields[ll] = @fields_off[ll]
			end
		}
		@opcode_list << o
	end

	def init
		@fields_mask = {:f => 0x7f, :b => 0x7, :k => 0xff, :klong => 0x3ff, :d => 1 }
		@props_allowed = {:setip => true, :saveip => true, :stopexec => true }
		@fields_off = { :f => 0, :b => 7, :k => 0, :klong => 0, :d => 7, :d => 7 }

		addop 'addwf', 0b00_0111_0000_0000, :f, :d
		addop 'andwf', 0b00_0101_0000_0000, :f, :d
		addop 'clrf',  0b00_0001_1000_0000, :f
		addop 'clrw',  0b00_0001_0000_0000		# 00_0001_0xxx_xxxx
		addop 'comf',  0b00_1001_0000_0000, :f, :d
		addop 'decf',  0b00_0011_0000_0000, :f, :d
		addop 'decfsz',0b00_1011_0000_0000, :f, :d
		addop 'incf',  0b00_1010_0000_0000, :f, :d
		addop 'incfsz',0b00_1111_0000_0000, :f, :d
		addop 'iorwf', 0b00_0100_0000_0000, :f, :d
		addop 'movf',  0b00_1000_0000_0000, :f, :d
		addop 'movwf', 0b00_0000_1000_0000, :f
		addop 'nop',   0b00_0000_0000_0000		# 00_0000_0xx0_0000
		addop 'rlf',   0b00_1101_0000_0000, :f, :d
		addop 'rrf',   0b00_1100_0000_0000, :f, :d
		addop 'subwf', 0b00_0010_0000_0000, :f, :d
		addop 'swapf', 0b00_1110_0000_0000, :f, :d
		addop 'xorwf', 0b00_0110_0000_0000, :f, :d

		addop 'bcf',   0b01_0000_0000_0000, :f, :b
		addop 'bsf',   0b01_0100_0000_0000, :f, :b
		addop 'btfsc', 0b01_1000_0000_0000, :f, :b, :setip
		addop 'btfss', 0b01_1100_0000_0000, :f, :b, :setip

		addop 'addlw', 0b11_1110_0000_0000, :k		# 00_000x_0000_0000
		addop 'andlw', 0b11_1001_0000_0000, :k
		addop 'call',  0b10_0000_0000_0000, :klong, :setip, :stopexec, :saveip
		addop 'clrwdt',0b00_0000_0110_0100
		addop 'goto',  0b10_1000_0000_0000, :klong, :setip, :stopexec
		addop 'iorlw', 0b11_1000_0000_0000, :k
		addop 'movlw', 0b11_0000_0000_0000, :k		# 00_00xx_0000_0000
		addop 'retfie',0b00_0000_0000_1001, :setip, :stopexec
		addop 'retlw', 0b11_0100_0000_0000, :k, :setip, :stopexec	# 00_00xx_0000_0000
		addop 'return',0b00_0000_0000_1000, :setip, :stopexec
		addop 'sleep', 0b00_0000_0110_0011
		addop 'sublw', 0b11_1100_0000_0000, :k		# 00_000x_0000_0000
		addop 'xorlw', 0b11_1010_0000_0000, :k
	end
end
end
