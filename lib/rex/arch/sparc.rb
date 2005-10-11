#!/usr/bin/ruby

module Rex
module Arch

#
# Everything here is mostly stolen from vlad's perl x86 stuff
#
module Sparc

	#
	# Register number constants
	#
	RegisterNumber =
		{
			'g0' =>  0, 'g1' =>  1, 'g2' =>  2, 'g3' =>  3,
			'g4' =>  4, 'g5' =>  5, 'g6' =>  6, 'g7' =>  7,
			'o0' =>  8, 'o1' =>  9, 'o2' => 10, 'o3' => 11,
			'o4' => 12, 'o5' => 13, 'o6' => 14, 'o7' => 15,
			'l0' => 16, 'l1' => 17, 'l2' => 18, 'l3' => 19,
			'l4' => 20, 'l5' => 21, 'l6' => 22, 'l7' => 23,
			'i0' => 24, 'i1' => 25, 'i2' => 26, 'i3' => 27,
			'i4' => 28, 'i5' => 29, 'i6' => 30, 'i7' => 31,
		}

	def self.sethi(constant, dst) 
		[ 
		  (RegisterNumber[dst] << 25) | 
		  (4 << 22) | 
		  (constant >> 10)
		].pack('N')
	end

	def self.ori(src, constant, dst)
		[ 
		  (2 << 30) | 
		  (RegisterNumber[dst] << 25) | 
		  (2 << 19) | 
		  (RegisterNumber[src] << 14) | 
		  (1 << 13) | 
		  (constant & 0x1fff)
		].pack('N')
	end

	def self.set(constant, dst)
		if (constant <= 4096 and constant >= 0)
			ori('g0', constant, dst)
		elsif (constant & 0x3ff)
			set_dword(constant, dst)
		else
			sethi(constant, dst)
		end
	end

	def self.set_dword(constant, dst)
		sethi(constant, dst) + ori(dst, constant & 0x3ff, dst)
	end

end

end end
