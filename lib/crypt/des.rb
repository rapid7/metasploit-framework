module Cipher
	#
	# = Brief
	#
	# The Cipher::DES class allows for encryption and decryption of plain
	# text using the "Data Encryption Standard". This version is the modified
	# version which is part of the VNC authentication scheme.
	#
	# Usage is pretty straight forward:
	#
	#   des = Cipher::DES.new 'mysecretkey', :encrypt
	#   str = des.update 'plain text'
	#   str << des.update 'more plain text'
	#   str << final
	#
	# Or just use the shortcut class methods:
	#
	#   str = Cipher::DES.encrypt 'mysecretkey', 'plain text'
	#
	# = About
	#
	# This code was ported from the file "d3des.c", for portability reasons.
	# It is not expected to be quick, but is only being used currently for the
	# VNC authentication handshake. If you wanted to cipher a lot of text, you
	# should probably compile the original C as an extension.
	#
	# I've included the following copyright info from the C source verbatim:
	#
	#   This is D3DES (V5.09) by Richard Outerbridge with the double and
	#   triple-length support removed for use in VNC.  Also the bytebit[] array
	#   has been reversed so that the most significant bit in each byte of the
	#   key is ignored, not the least significant.
	#
	#   These changes are:
	#   Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
	#
	#   This software is distributed in the hope that it will be useful,
	#   but WITHOUT ANY WARRANTY; without even the implied warranty of
	#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	#
	#   D3DES (V5.09)
	#
	#   A portable, public domain, version of the Data Encryption Standard.
	#
	#   Written with Symantec's THINK (Lightspeed) C by Richard Outerbridge.
	#   Thanks to: Dan Hoey for his excellent Initial and Inverse permutation
	#   code;  Jim Gillogly & Phil Karn for the DES key schedule code; Dennis
	#   Ferguson, Eric Young and Dana How for comparing notes; and Ray Lau,
	#   for humouring me on.
	#
	#   Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
	#   (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.
	#
	class DES
		BLOCK_SIZE = 8

		attr_reader :key, :mode

		# Create a des cipher object. +key+ should be cipher key to use, and +mode+ should
		# be either <tt>:encrypt</tt> or <tt>:decrypt</tt>.
		#
		# It will expand +key+ to be 8 bytes by padding with null bytes. If it is longer than
		# 8 bytes, the additional data is discarded.
		def initialize key, mode
			unless [:encrypt, :decrypt].include? mode
				raise ArgumentError, 'invalid mode argument - %s' % mode
			end
			@mode = mode

			# ensure key is 8 bytes. pad with nulls as needed
			key = key[0, BLOCK_SIZE]
			key << 0.chr * (BLOCK_SIZE - key.length)
			@key = key

			# now expand the key schedule
			@keys = self.class.send :prepare_key_stage2, self.class.send(:prepare_key_stage1, key, mode)

			# this internal buffer is used because we must process data in chunks of 8 bytes
			@buf = ''
		end

		# This updates the cipher with +data+, returning any available ciphered output. The +data+ is
		# processed in blocks of 8 bytes, so any residual is added to an internal buffer.
		def update data
			result = ''
			data = @buf + data unless @buf.empty?
			num_blocks, residual = data.length.divmod BLOCK_SIZE
			num_blocks.times do |i|
				block = data[i * BLOCK_SIZE, BLOCK_SIZE].unpack('N2')
				result << self.class.send(:desfunc, block, @keys).pack('N2')
			end
			@buf = residual == 0 ? '' : data[-residual..-1]
			result
		end

		# This flushes the internal buffer by padding it out with null bytes, and doing a final
		# DES round. Note that this means the ciphered text is always padded out to a multiple of
		# 8 bytes.
		def final
			if @buf.empty?
				''
			else
				update 0.chr * (BLOCK_SIZE - @buf.length)
			end
		end

		# A shortcut method to create a cipher object using +key+, and fully encrypt +data+
		def self.encrypt key, data
			des = new key, :encrypt
			des.update(data) << des.final
		end

		# A shortcut method to create a cipher object using +key+, and fully decrypt +data+
		def self.decrypt key, data
			des = new key, :decrypt
			des.update(data) << des.final
		end

		class << self #:nodoc: all
			BYTEBIT	= [
				01, 02, 04, 010, 020, 040, 0100, 0200
			]

			BIGBYTE = [
				0x800000, 0x400000, 0x200000, 0x100000,
				0x080000, 0x040000, 0x020000, 0x010000,
				0x008000, 0x004000, 0x002000, 0x001000,
				0x000800, 0x000400, 0x000200, 0x000100,
				0x000080, 0x000040, 0x000020, 0x000010,
				0x000008, 0x000004, 0x000002, 0x000001
			]

			# Use the key schedule specified in the Standard (ANSI X3.92-1981).

			PC1 = [
				56, 48, 40, 32, 24, 16,  8,	 0, 57, 49, 41, 33, 25, 17,
				 9,  1, 58, 50, 42, 34, 26,	18, 10,  2, 59, 51, 43, 35,
				62, 54, 46, 38, 30, 22, 14,	 6, 61, 53, 45, 37, 29, 21,
				13,  5, 60, 52, 44, 36, 28,	20, 12,  4, 27, 19, 11,  3
			]

			TOTROT = [
				1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
			]

			PC2 = [
				13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
				22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
				40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
				43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
			]

		private

			#
			# Prepares +key+ to be used
			#
			# +key+:: String
			# +mode+:: :encrypt or :decrypt
			#
			# Thanks to James Gillogly & Phil Karn!
			#
			# corresponds to "deskey"
			#
			def prepare_key_stage1 key, mode
				pcr = [nil] * 56
				kn = [nil] * 32

				pc1m = (0...56).map do |j|
					l = PC1[j]
					m = l & 07
					(key[l >> 3] & BYTEBIT[m]) != 0 ? 1 : 0;
				end

				16.times do |i|
					m = mode == :encrypt ? i << 1 : (15 - i) << 1
					n = m + 1
					kn[m] = kn[n] = 0
					28.times do |j|
						l = (j + TOTROT[i]) % 28
						pcr[j] = pc1m[l]
						pcr[j + 28] = pc1m[l + 28]
					end
					24.times do |j|
						kn[m] |= BIGBYTE[j] if pcr[PC2[j]] != 0
						kn[n] |= BIGBYTE[j] if pcr[PC2[j+24]] != 0
					end
				end

				kn
			end

			# corresponds to "cookey"
			def prepare_key_stage2(raw1)
				cook = []

				16.times do |i|
					a = raw1[i * 2 + 0]
					b = raw1[i * 2 + 1]
					x  = (a & 0x00fc0000) << 6
					x |= (a & 0x00000fc0) << 10
					x |= (b & 0x00fc0000) >> 10
					x |= (b & 0x00000fc0) >> 6
					cook << x
					x  = (a & 0x0003f000) << 12
					x	|= (a & 0x0000003f) << 16
					x	|= (b & 0x0003f000) >> 4
					x |= (b & 0x0000003f)
					cook << x
				end

				cook
			end

			SP1 = [
				0x01010400, 0x00000000, 0x00010000, 0x01010404,
				0x01010004, 0x00010404, 0x00000004, 0x00010000,
				0x00000400, 0x01010400, 0x01010404, 0x00000400,
				0x01000404, 0x01010004, 0x01000000, 0x00000004,
				0x00000404, 0x01000400, 0x01000400, 0x00010400,
				0x00010400, 0x01010000, 0x01010000, 0x01000404,
				0x00010004, 0x01000004, 0x01000004, 0x00010004,
				0x00000000, 0x00000404, 0x00010404, 0x01000000,
				0x00010000, 0x01010404, 0x00000004, 0x01010000,
				0x01010400, 0x01000000, 0x01000000, 0x00000400,
				0x01010004, 0x00010000, 0x00010400, 0x01000004,
				0x00000400, 0x00000004, 0x01000404, 0x00010404,
				0x01010404, 0x00010004, 0x01010000, 0x01000404,
				0x01000004, 0x00000404, 0x00010404, 0x01010400,
				0x00000404, 0x01000400, 0x01000400, 0x00000000,
				0x00010004, 0x00010400, 0x00000000, 0x01010004
			]

			SP2 = [
				0x80108020, 0x80008000, 0x00008000, 0x00108020,
				0x00100000, 0x00000020, 0x80100020, 0x80008020,
				0x80000020, 0x80108020, 0x80108000, 0x80000000,
				0x80008000, 0x00100000, 0x00000020, 0x80100020,
				0x00108000, 0x00100020, 0x80008020, 0x00000000,
				0x80000000, 0x00008000, 0x00108020, 0x80100000,
				0x00100020, 0x80000020, 0x00000000, 0x00108000,
				0x00008020, 0x80108000, 0x80100000, 0x00008020,
				0x00000000, 0x00108020, 0x80100020, 0x00100000,
				0x80008020, 0x80100000, 0x80108000, 0x00008000,
				0x80100000, 0x80008000, 0x00000020, 0x80108020,
				0x00108020, 0x00000020, 0x00008000, 0x80000000,
				0x00008020, 0x80108000, 0x00100000, 0x80000020,
				0x00100020, 0x80008020, 0x80000020, 0x00100020,
				0x00108000, 0x00000000, 0x80008000, 0x00008020,
				0x80000000, 0x80100020, 0x80108020, 0x00108000
			]

			SP3 = [
				0x00000208, 0x08020200, 0x00000000, 0x08020008,
				0x08000200, 0x00000000, 0x00020208, 0x08000200,
				0x00020008, 0x08000008, 0x08000008, 0x00020000,
				0x08020208, 0x00020008, 0x08020000, 0x00000208,
				0x08000000, 0x00000008, 0x08020200, 0x00000200,
				0x00020200, 0x08020000, 0x08020008, 0x00020208,
				0x08000208, 0x00020200, 0x00020000, 0x08000208,
				0x00000008, 0x08020208, 0x00000200, 0x08000000,
				0x08020200, 0x08000000, 0x00020008, 0x00000208,
				0x00020000, 0x08020200, 0x08000200, 0x00000000,
				0x00000200, 0x00020008, 0x08020208, 0x08000200,
				0x08000008, 0x00000200, 0x00000000, 0x08020008,
				0x08000208, 0x00020000, 0x08000000, 0x08020208,
				0x00000008, 0x00020208, 0x00020200, 0x08000008,
				0x08020000, 0x08000208, 0x00000208, 0x08020000,
				0x00020208, 0x00000008, 0x08020008, 0x00020200
			]

			SP4 = [
				0x00802001, 0x00002081, 0x00002081, 0x00000080,
				0x00802080, 0x00800081, 0x00800001, 0x00002001,
				0x00000000, 0x00802000, 0x00802000, 0x00802081,
				0x00000081, 0x00000000, 0x00800080, 0x00800001,
				0x00000001, 0x00002000, 0x00800000, 0x00802001,
				0x00000080, 0x00800000, 0x00002001, 0x00002080,
				0x00800081, 0x00000001, 0x00002080, 0x00800080,
				0x00002000, 0x00802080, 0x00802081, 0x00000081,
				0x00800080, 0x00800001, 0x00802000, 0x00802081,
				0x00000081, 0x00000000, 0x00000000, 0x00802000,
				0x00002080, 0x00800080, 0x00800081, 0x00000001,
				0x00802001, 0x00002081, 0x00002081, 0x00000080,
				0x00802081, 0x00000081, 0x00000001, 0x00002000,
				0x00800001, 0x00002001, 0x00802080, 0x00800081,
				0x00002001, 0x00002080, 0x00800000, 0x00802001,
				0x00000080, 0x00800000, 0x00002000, 0x00802080
			]

			SP5 = [
				0x00000100, 0x02080100, 0x02080000, 0x42000100,
				0x00080000, 0x00000100, 0x40000000, 0x02080000,
				0x40080100, 0x00080000, 0x02000100, 0x40080100,
				0x42000100, 0x42080000, 0x00080100, 0x40000000,
				0x02000000, 0x40080000, 0x40080000, 0x00000000,
				0x40000100, 0x42080100, 0x42080100, 0x02000100,
				0x42080000, 0x40000100, 0x00000000, 0x42000000,
				0x02080100, 0x02000000, 0x42000000, 0x00080100,
				0x00080000, 0x42000100, 0x00000100, 0x02000000,
				0x40000000, 0x02080000, 0x42000100, 0x40080100,
				0x02000100, 0x40000000, 0x42080000, 0x02080100,
				0x40080100, 0x00000100, 0x02000000, 0x42080000,
				0x42080100, 0x00080100, 0x42000000, 0x42080100,
				0x02080000, 0x00000000, 0x40080000, 0x42000000,
				0x00080100, 0x02000100, 0x40000100, 0x00080000,
				0x00000000, 0x40080000, 0x02080100, 0x40000100
			]

			SP6 = [
				0x20000010, 0x20400000, 0x00004000, 0x20404010,
				0x20400000, 0x00000010, 0x20404010, 0x00400000,
				0x20004000, 0x00404010, 0x00400000, 0x20000010,
				0x00400010, 0x20004000, 0x20000000, 0x00004010,
				0x00000000, 0x00400010, 0x20004010, 0x00004000,
				0x00404000, 0x20004010, 0x00000010, 0x20400010,
				0x20400010, 0x00000000, 0x00404010, 0x20404000,
				0x00004010, 0x00404000, 0x20404000, 0x20000000,
				0x20004000, 0x00000010, 0x20400010, 0x00404000,
				0x20404010, 0x00400000, 0x00004010, 0x20000010,
				0x00400000, 0x20004000, 0x20000000, 0x00004010,
				0x20000010, 0x20404010, 0x00404000, 0x20400000,
				0x00404010, 0x20404000, 0x00000000, 0x20400010,
				0x00000010, 0x00004000, 0x20400000, 0x00404010,
				0x00004000, 0x00400010, 0x20004010, 0x00000000,
				0x20404000, 0x20000000, 0x00400010, 0x20004010
			]

			SP7 = [
				0x00200000, 0x04200002, 0x04000802, 0x00000000,
				0x00000800, 0x04000802, 0x00200802, 0x04200800,
				0x04200802, 0x00200000, 0x00000000, 0x04000002,
				0x00000002, 0x04000000, 0x04200002, 0x00000802,
				0x04000800, 0x00200802, 0x00200002, 0x04000800,
				0x04000002, 0x04200000, 0x04200800, 0x00200002,
				0x04200000, 0x00000800, 0x00000802, 0x04200802,
				0x00200800, 0x00000002, 0x04000000, 0x00200800,
				0x04000000, 0x00200800, 0x00200000, 0x04000802,
				0x04000802, 0x04200002, 0x04200002, 0x00000002,
				0x00200002, 0x04000000, 0x04000800, 0x00200000,
				0x04200800, 0x00000802, 0x00200802, 0x04200800,
				0x00000802, 0x04000002, 0x04200802, 0x04200000,
				0x00200800, 0x00000000, 0x00000002, 0x04200802,
				0x00000000, 0x00200802, 0x04200000, 0x00000800,
				0x04000002, 0x04000800, 0x00000800, 0x00200002
			]

			SP8 = [
				0x10001040, 0x00001000, 0x00040000, 0x10041040,
				0x10000000, 0x10001040, 0x00000040, 0x10000000,
				0x00040040, 0x10040000, 0x10041040, 0x00041000,
				0x10041000, 0x00041040, 0x00001000, 0x00000040,
				0x10040000, 0x10000040, 0x10001000, 0x00001040,
				0x00041000, 0x00040040, 0x10040040, 0x10041000,
				0x00001040, 0x00000000, 0x00000000, 0x10040040,
				0x10000040, 0x10001000, 0x00041040, 0x00040000,
				0x00041040, 0x00040000, 0x10041000, 0x00001000,
				0x00000040, 0x10040040, 0x00001000, 0x00041040,
				0x10001000, 0x00000040, 0x10000040, 0x10040000,
				0x10040040, 0x10000000, 0x00040000, 0x10001040,
				0x00000000, 0x10041040, 0x00040040, 0x10000040,
				0x10040000, 0x10001000, 0x10001040, 0x00000000,
				0x10041040, 0x00041000, 0x00041000, 0x00001040,
				0x00001040, 0x00040040, 0x10000000, 0x10041000
			]

			def desfunc block, keys
				leftt = block[0]
				right = block[1]

				work = ((leftt >> 4) ^ right) & 0x0f0f0f0f
				right ^= work
				leftt ^= (work << 4)
				work = ((leftt >> 16) ^ right) & 0x0000ffff
				right ^= work
				leftt ^= (work << 16)
				work = ((right >> 2) ^ leftt) & 0x33333333
				leftt ^= work
				right ^= (work << 2)
				work = ((right >> 8) ^ leftt) & 0x00ff00ff
				leftt ^= work
				right ^= (work << 8)
				right = ((right << 1) | ((right >> 31) & 1)) & 0xffffffff
				work = (leftt ^ right) & 0xaaaaaaaa
				leftt ^= work
				right ^= work
				leftt = ((leftt << 1) | ((leftt >> 31) & 1)) & 0xffffffff

				8.times do |i|
					work  = (right << 28) | (right >> 4)
					work ^= keys[i * 4 + 0]
					fval  = SP7[ work		 & 0x3f]
					fval |= SP5[(work >>  8) & 0x3f]
					fval |= SP3[(work >> 16) & 0x3f]
					fval |= SP1[(work >> 24) & 0x3f]
					work  = right ^ keys[i * 4 + 1]
					fval |= SP8[ work		 & 0x3f]
					fval |= SP6[(work >>  8) & 0x3f]
					fval |= SP4[(work >> 16) & 0x3f]
					fval |= SP2[(work >> 24) & 0x3f]
					leftt ^= fval
					work  = (leftt << 28) | (leftt >> 4)
					work ^= keys[i * 4 + 2]
					fval  = SP7[ work		 & 0x3f]
					fval |= SP5[(work >>  8) & 0x3f]
					fval |= SP3[(work >> 16) & 0x3f]
					fval |= SP1[(work >> 24) & 0x3f]
					work  = leftt ^ keys[i * 4 + 3]
					fval |= SP8[ work		 & 0x3f]
					fval |= SP6[(work >>  8) & 0x3f]
					fval |= SP4[(work >> 16) & 0x3f]
					fval |= SP2[(work >> 24) & 0x3f]
					right ^= fval
				end

				right = ((right << 31) | (right >> 1)) & 0xffffffff
				work = (leftt ^ right) & 0xaaaaaaaa
				leftt ^= work
				right ^= work
				leftt = ((leftt << 31) | (leftt >> 1)) & 0xffffffff
				work = ((leftt >> 8) ^ right) & 0x00ff00ff
				right ^= work
				leftt ^= (work << 8)
				work = ((leftt >> 2) ^ right) & 0x33333333
				right ^= work
				leftt ^= (work << 2)
				work = ((right >> 16) ^ leftt) & 0x0000ffff
				leftt ^= work
				right ^= (work << 16)
				work = ((right >> 4) ^ leftt) & 0x0f0f0f0f
				leftt ^= work
				right ^= (work << 4)

				[right, leftt]
			end
		end
	end
end

