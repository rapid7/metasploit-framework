#! /usr/bin/ruby -w

require 'iconv'
require 'date'
require 'stringio'
require 'tempfile'


require 'ole/base'
require 'ole/types'
require 'ole/io_helpers'

module Ole # :nodoc:

	# 
	# = Introduction
	#
	# <tt>Ole::Storage</tt> is a simple class intended to abstract away details of the
	# access to OLE2 structured storage files, such as those produced by
	# Microsoft Office, eg *.doc, *.msg etc.
	#
	# Initially based on chicago's libole, source available at
	# http://prdownloads.sf.net/chicago/ole.tgz
	# Later augmented with some corrections by inspecting pole, and (purely
	# for header definitions) gsf.
	#
	# = Usage
	#
	# Usage should be fairly straight forward:
	#
	#   # get the parent ole storage object
	#   ole = Ole::Storage.open 'myfile.msg', 'r+'
	#   # => #<Ole::Storage io=#<File:myfile.msg> root=#<Dirent:"Root Entry">>
	#   # read some data
	#   ole.root[1].read 4
	#   # => "\001\000\376\377"
	#   # get the top level root object and output a tree structure for
	#   # debugging
	#   puts ole.root.to_tree
	#   # =>
	#   - #<Dirent:"Root Entry" size=3840 time="2006-11-03T00:52:53Z">
	#     |- #<Dirent:"__nameid_version1.0" size=0 time="2006-11-03T00:52:53Z">
	#     |  |- #<Dirent:"__substg1.0_00020102" size=16 data="CCAGAAAAAADAAA...">
	#     ...
	#     |- #<Dirent:"__substg1.0_8002001E" size=4 data="MTEuMA==">
	#     |- #<Dirent:"__properties_version1.0" size=800 data="AAAAAAAAAAABAA...">
	#     \- #<Dirent:"__recip_version1.0_#00000000" size=0 time="2006-11-03T00:52:53Z">
	#        |- #<Dirent:"__substg1.0_0FF60102" size=4 data="AAAAAA==">
	#   	 ...
	#   # write some data, and finish up (note that open is 'r+', so this overwrites
	#   # but doesn't truncate)
	#   ole.root["\001CompObj"].open { |f| f.write "blah blah" }
	#   ole.close
	#
	# = TODO
	#
	# 1. tests. lock down how things work at the moment - mostly good.
	#    create from scratch works now, as does copying in a subtree of another doc, so
	#    ole embedded attachment serialization works now. i can save embedded xls in an msg
	#    into a separate file, and open it. this was a goal. now i would want to implemenet
	#    to_mime conversion for embedded attachments, that serializes them to ole, but handles
	#    some separately like various meta file types as plain .wmf attachments perhaps. this
	#    will give pretty good .eml's from emails with embedded attachments.
	#    the other todo is .rtf output, with full support for embedded ole objects...
	# 2. lots of tidying up
	#    - main FIXME's in this regard are:
	#      * the custom header cruft for Header and Dirent needs some love.
	#      * i have a number of classes doing load/save combos: Header, AllocationTable, Dirent,
	#        and, in a manner of speaking, but arguably different, Storage itself.
	#        they have differing api's which would be nice to clean.
	#        AllocationTable::Big must be created aot now, as it is used for all subsequent reads.
	#     * ole types need work, can't serialize datetime at the moment.
	# 3. need to fix META_BAT support in #flush.
	#
	class Storage
		VERSION = '1.1.1'

		# The top of the ole tree structure
		attr_reader :root
		# The tree structure in its original flattened form. only valid after #load, or #flush.
		attr_reader :dirents
		# The underlying io object to/from which the ole object is serialized, whether we
		# should close it, and whether it is writeable
		attr_reader :io, :close_parent, :writeable
		# Low level internals, you probably shouldn't need to mess with these
		attr_reader :header, :bbat, :sbat, :sb_file

		# maybe include an option hash, and allow :close_parent => true, to be more general.
		# +arg+ should be either a file, or an +IO+ object, and needs to be seekable.
		def initialize arg, mode=nil
			# get the io object
			@close_parent, @io = if String === arg
				[true, open(arg, mode || 'rb')]
			else
				raise 'unable to specify mode string with io object' if mode
				[false, arg]
			end
			# do we have this file opened for writing? don't know of a better way to tell
			@writeable = begin
				@io.flush
				true
			rescue IOError
				false
			end
			# silence undefined warning in clear
			@sb_file = nil
			# if the io object has data, we should load it, otherwise start afresh
			if @io.size > 0; load
			else clear
			end
		end

		def self.new arg, mode=nil
			ole = super
			if block_given?
				begin   yield ole
				ensure; ole.close
				end
			else ole
			end
		end

		class << self
			# encouraged
			alias open :new
			# deprecated
			alias load :new
		end

		# load document from file.
		def load
			# we always read 512 for the header block. if the block size ends up being different,
			# what happens to the 109 fat entries. are there more/less entries?
			@io.rewind
			header_block = @io.read 512
			@header = Header.load header_block

			# create an empty bbat
			@bbat = AllocationTable::Big.new self
			# extra mbat blocks
			mbat_blocks = (0...@header.num_mbat).map { |i| i + @header.mbat_start }
			bbat_chain = (header_block[Header::SIZE..-1] + @bbat.read(mbat_blocks)).unpack 'L*'
			# am i using num_bat in the right way?
			@bbat.load @bbat.read(bbat_chain[0, @header.num_bat])
	
			# get block chain for directories, read it, then split it into chunks and load the
			# directory entries. semantics changed - used to cut at first dir where dir.type == 0
			@dirents = @bbat.read(@header.dirent_start).scan(/.{#{Dirent::SIZE}}/mo).
				map { |str| Dirent.load self, str }.reject { |d| d.type_id == 0 }

			# now reorder from flat into a tree
			# links are stored in some kind of balanced binary tree
			# check that everything is visited at least, and at most once
			# similarly with the blocks of the file.
			# was thinking of moving this to Dirent.to_tree instead.
			class << @dirents
				def to_tree idx=0
					return [] if idx == Dirent::EOT
					d = self[idx]
					d.children = to_tree d.child
					raise "directory #{d.inspect} used twice" if d.idx
					d.idx = idx
					to_tree(d.prev) + [d] + to_tree(d.next)
				end
			end

			@root = @dirents.to_tree.first
			Log.warn "root name was #{@root.name.inspect}" unless @root.name == 'Root Entry'
			unused = @dirents.reject(&:idx).length
			Log.warn "* #{unused} unused directories" if unused > 0

			# FIXME i don't currently use @header.num_sbat which i should
			# hmm. nor do i write it. it means what exactly again?
			@sb_file = RangesIOResizeable.new @bbat, @root.first_block, @root.size
			@sbat = AllocationTable::Small.new self
			@sbat.load @bbat.read(@header.sbat_start)
		end

		def close
			flush if @writeable
			@sb_file.close
			@io.close if @close_parent
		end

		# should have a #open_dirent i think. and use it in load and flush. neater.
		# also was thinking about Dirent#open_padding. then i can more easily clean up the padding
		# to be 0.chr
=begin
thoughts on fixes:
1. reterminate any chain not ending in EOC. 
2. pass through all chain heads looking for collisions, and making sure nothing points to them
   (ie they are really heads).
3. we know the locations of the bbat data, and mbat data. ensure that there are placeholder blocks
   in the bat for them.
this stuff will ensure reliability of input better. otherwise, its actually worth doing a repack
directly after read, to ensure the above is probably acounted for, before subsequent writes possibly
destroy things.
=end
		def flush
			# recreate dirs from our tree, split into dirs and big and small files
			@root.type = :root
			# for now.
			@root.name = 'Root Entry'
			@root.first_block = @sb_file.first_block
			@root.size = @sb_file.size
			@dirents = @root.flatten
			#dirs, files = @dirents.partition(&:dir?)
			#big_files, small_files = files.partition { |file| file.size > @header.threshold }

			# maybe i should move the block form up to RangesIO, and get it for free at all levels.
			# Dirent#open gets block form for free then
			io = RangesIOResizeable.new @bbat, @header.dirent_start
			io.truncate 0
			@dirents.each { |dirent| io.write dirent.save }
			padding = (io.size / @bbat.block_size.to_f).ceil * @bbat.block_size - io.size
			#p [:padding, padding]
			io.write 0.chr * padding
			@header.dirent_start = io.first_block
			io.close

			# similarly for the sbat data.
			io = RangesIOResizeable.new @bbat, @header.sbat_start
			io.truncate 0
			io.write @sbat.save
			@header.sbat_start = io.first_block
			@header.num_sbat = @bbat.chain(@header.sbat_start).length
			io.close

			# what follows will be slightly more complex for the bat fiddling.

			# create RangesIOResizeable hooked up to the bbat. use that to claim bbat blocks using
			# truncate. then when its time to write, convert that chain and some chunk of blocks at
			# the end, into META_BAT blocks. write out the chain, and those meta bat blocks, and its
			# done.

			@bbat.table.map! do |b|
				b == AllocationTable::BAT || b == AllocationTable::META_BAT ?
					AllocationTable::AVAIL : b
			end
			io = RangesIOResizeable.new @bbat, AllocationTable::EOC
			# use crappy loop for now:
			while true
				bbat_data = @bbat.save
				#mbat_data = bbat_data.length / @bbat.block_size * 4
				mbat_chain = @bbat.chain io.first_block
				raise NotImplementedError, "don't handle writing out extra META_BAT blocks yet" if mbat_chain.length > 109
				# so we can ignore meta blocks in this calculation:
				break if io.size >= bbat_data.length # it shouldn't be bigger right?
				# this may grow the bbat, depending on existing available blocks
				io.truncate bbat_data.length
			end

			# now extract the info we want:
			ranges = io.ranges
			mbat_chain = @bbat.chain io.first_block
			io.close
			mbat_chain.each { |b| @bbat.table[b] = AllocationTable::BAT }
			@header.num_bat = mbat_chain.length
			#p @bbat.truncated_table
			#p ranges
			#p mbat_chain
			# not resizeable!
			io = RangesIO.new @io, ranges
			io.write @bbat.save
			io.close
			mbat_chain += [AllocationTable::AVAIL] * (109 - mbat_chain.length)
			@header.mbat_start = AllocationTable::EOC
			@header.num_mbat = 0

=begin
			bbat_data = new_bbat.save
			# must exist as linear chain stored in header.
			@header.num_bat = (bbat_data.length / new_bbat.block_size.to_f).ceil
			base = io.pos / new_bbat.block_size - 1
			io.write bbat_data
			# now that spanned a number of blocks:
			mbat = (0...@header.num_bat).map { |i| i + base }
			mbat += [AllocationTable::AVAIL] * (109 - mbat.length) if mbat.length < 109
			header_mbat = mbat[0...109]
			other_mbat_data = mbat[109..-1].pack 'L*'
			@header.mbat_start = base + @header.num_bat
			@header.num_mbat = (other_mbat_data.length / new_bbat.block_size.to_f).ceil
			io.write other_mbat_data
=end

			@root.type = :dir

			# now seek back and write the header out
			@io.seek 0
			@io.write @header.save + mbat_chain.pack('L*')
			@io.flush
		end

		def clear
			# first step though is to support modifying pre-existing and saving, then this
			# missing gap will be fairly straight forward - essentially initialize to
			# equivalent of loading an empty ole document.
			#raise NotImplementedError, 'unable to create new ole objects from scratch as yet'
			Log.warn 'creating new ole storage object on non-writable io' unless @writeable
			@header = Header.new
			@bbat = AllocationTable::Big.new self
			@root = Dirent.new self, :dir
			@root.name = 'Root Entry'
			@dirents = [@root]
			@root.idx = 0
			@root.children = []
			# size shouldn't display for non-files
			@root.size = 0
			@sb_file.close if @sb_file
			@sb_file = RangesIOResizeable.new @bbat, AllocationTable::EOC
			@sbat = AllocationTable::Small.new self
			# throw everything else the hell away
			@io.truncate 0
		end

		# could be useful with mis-behaving ole documents. or to just clean them up.
		def repack temp=:file
			case temp
			when :file; Tempfile.open 'w+', &method(:repack_using_io)
			when :mem;  StringIO.open(&method(:repack_using_io))
			else raise "unknown temp backing #{temp.inspect}"
			end
		end

		def repack_using_io temp_io
			@io.rewind
			IO.copy @io, temp_io
			clear
			Storage.open temp_io do |temp_ole|
				temp_ole.root.type = :dir
				Dirent.copy temp_ole.root, root
			end
		end

		def bat_for_size size
			# note >=, not > previously.
			size >= @header.threshold ? @bbat : @sbat
		end

		def inspect
			"#<#{self.class} io=#{@io.inspect} root=#{@root.inspect}>"
		end

		# A class which wraps the ole header
		class Header < Struct.new(
				:magic, :clsid, :minor_ver, :major_ver, :byte_order, :b_shift, :s_shift,
				:reserved, :csectdir, :num_bat, :dirent_start, :transacting_signature, :threshold,
				:sbat_start, :num_sbat, :mbat_start, :num_mbat
			)
			PACK = 'a8 a16 S2 a2 S2 a6 L3 a4 L5'
			SIZE = 0x4c
			# i have seen it pointed out that the first 4 bytes of hex,
			# 0xd0cf11e0, is supposed to spell out docfile. hmmm :)
			MAGIC = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # expected value of Header#magic
			# what you get if creating new header from scratch.
			# AllocationTable::EOC isn't available yet. meh.
			EOC = 0xfffffffe
			DEFAULT = [
				MAGIC, 0.chr * 16, 59, 3, "\xfe\xff", 9, 6,
				0.chr * 6, 0, 1, EOC, 0.chr * 4,
				4096, EOC, 0, EOC, 0
			]

			# 2 basic initializations, from scratch, or from a data string.
			# from scratch will be geared towards creating a new ole object
			def initialize *values
				super(*(values.empty? ? DEFAULT : values))
				validate!
			end

			def self.load str
				Header.new(*str.unpack(PACK))
			end

			def save
				to_a.pack PACK
			end

			def validate!
				raise "OLE2 signature is invalid" unless magic == MAGIC
				if num_bat == 0 or # is that valid for a completely empty file?
					 # not sure about this one. basically to do max possible bat given size of mbat
					 num_bat > 109 && num_bat > 109 + num_mbat * (1 << b_shift - 2) or
					 # shouldn't need to use the mbat as there is enough space in the header block
					 num_bat < 109 && num_mbat != 0 or
					 # given the size of the header is 76, if b_shift <= 6, blocks address the header.
					 s_shift > b_shift or b_shift <= 6 or b_shift >= 31 or
					 # we only handle little endian
					 byte_order != "\xfe\xff"
					raise "not valid OLE2 structured storage file"
				end
				# relaxed this, due to test-msg/qwerty_[1-3]*.msg they all had
				# 3 for this value. 
				# transacting_signature != "\x00" * 4 or
				if threshold != 4096 or
					 num_mbat == 0 && mbat_start != AllocationTable::EOC or
					 reserved != "\x00" * 6
					Log.warn "may not be a valid OLE2 structured storage file"
				end
				true
			end
		end

		#
		# +AllocationTable+'s hold the chains corresponding to files. Given
		# an initial index, <tt>AllocationTable#chain</tt> follows the chain, returning
		# the blocks that make up that file.
		#
		# There are 2 allocation tables, the bbat, and sbat, for big and small
		# blocks respectively. The block chain should be loaded using either
		# <tt>Storage#read_big_blocks</tt> or <tt>Storage#read_small_blocks</tt>
		# as appropriate.
		#
		# Whether or not big or small blocks are used for a file depends on
		# whether its size is over the <tt>Header#threshold</tt> level.
		#
		# An <tt>Ole::Storage</tt> document is serialized as a series of directory objects,
		# which are stored in blocks throughout the file. The blocks are either
		# big or small, and are accessed using the <tt>AllocationTable</tt>.
		#
		# The bbat allocation table's data is stored in the spare room in the header
		# block, and in extra blocks throughout the file as referenced by the meta
		# bat.  That chain is linear, as there is no higher level table.
		#
		class AllocationTable
			# a free block (I don't currently leave any blocks free), although I do pad out
			# the allocation table with AVAIL to the block size.
			AVAIL		 = 0xffffffff
			EOC			 = 0xfffffffe # end of a chain
			# these blocks correspond to the bat, and aren't part of a file, nor available.
			# (I don't currently output these)
			BAT			 = 0xfffffffd
			META_BAT = 0xfffffffc

			attr_reader :ole, :io, :table, :block_size
			def initialize ole
				@ole = ole
				@table = []
			end

			def load data
				@table = data.unpack('L*')
			end

			def truncated_table
				# this strips trailing AVAILs. come to think of it, this has the potential to break
				# bogus ole. if you terminate using AVAIL instead of EOC, like I did before. but that is
				# very broken. however, if a chain ends with AVAIL, it should probably be fixed to EOC
				# at load time.
				temp = @table.reverse
				not_avail = temp.find { |b| b != AVAIL } and temp = temp[temp.index(not_avail)..-1]
				temp.reverse
			end

			def save
				table = truncated_table #@table
				# pad it out some
				num = @ole.bbat.block_size / 4
				# do you really use AVAIL? they probably extend past end of file, and may shortly
				# be used for the bat. not really good.
				table += [AVAIL] * (num - (table.length % num)) if (table.length % num) != 0
				table.pack 'L*'
			end

			# rewriting this to be non-recursive. it broke on a large attachment
			# building up the chain, causing a stack error. need tail-call elimination...
			def chain start
				a = []
				idx = start
				until idx >= META_BAT
					raise "broken allocationtable chain" if idx < 0 || idx > @table.length
					a << idx
					idx = @table[idx]
				end
				Log.warn "invalid chain terminator #{idx}" unless idx == EOC
				a
			end
			
			def ranges chain, size=nil
				chain = self.chain(chain) unless Array === chain
				blocks_to_ranges chain, size
			end

		# Turn a chain (an array given by +chain+) of big blocks, optionally
		# truncated to +size+, into an array of arrays describing the stretches of
		# bytes in the file that it belongs to.
		#
		# Big blocks are of size Ole::Storage::Header#b_size, and are stored
		# directly in the parent file.
			# truncate the chain if required
			# convert chain to ranges of the block size
			# truncate final range if required

			def blocks_to_ranges chain, size=nil
				chain = chain[0...(size.to_f / block_size).ceil] if size
				ranges = chain.map { |i| [block_size * i, block_size] }
				ranges.last[1] -= (ranges.length * block_size - size) if ranges.last and size
				ranges
			end

			# quick shortcut. chain can be either a head (in which case the table is used to
			# turn it into a chain), or a chain. it is converted to ranges, then to rangesio.
			# its not resizeable or migrateable. it probably could be resizeable though, using
			# self as the bat. but what would the first_block be?
			def open chain, size=nil
				io = RangesIO.new @io, ranges(chain, size)
				if block_given?
					begin   yield io
					ensure; io.close
					end
				else io
				end
			end

			def read chain, size=nil
				open chain, size, &:read
			end

			# ----------------------

			def get_free_block
				@table.each_index { |i| return i if @table[i] == AVAIL }
				@table.push AVAIL
				@table.length - 1
			end

			# must return first_block
			def resize_chain first_block, size
				new_num_blocks = (size / block_size.to_f).ceil
				blocks = chain first_block
				old_num_blocks = blocks.length
				if new_num_blocks < old_num_blocks
					# de-allocate some of our old blocks. TODO maybe zero them out in the file???
					(new_num_blocks...old_num_blocks).each { |i| @table[blocks[i]] = AVAIL }
					# if we have a chain, terminate it and return head, otherwise return EOC
					if new_num_blocks > 0
						@table[blocks[new_num_blocks-1]] = EOC
						first_block
					else EOC
					end
				elsif new_num_blocks > old_num_blocks
					# need some more blocks.
					last_block = blocks.last
					(new_num_blocks - old_num_blocks).times do
						block = get_free_block
						# connect the chain. handle corner case of blocks being [] initially
						if last_block
							@table[last_block] = block 
						else
							first_block = block
						end
						last_block = block
						# this is just to inhibit the problem where it gets picked as being a free block
						# again next time around.
						@table[last_block] = EOC
					end
					first_block
				else first_block
				end
			end

			class Big < AllocationTable
				def initialize(*args)
					super
					@block_size = 1 << @ole.header.b_shift
					@io = @ole.io
				end

				# Big blocks are kind of -1 based, in order to not clash with the header.
				def blocks_to_ranges blocks, size
					super blocks.map { |b| b + 1 }, size
				end
			end

			class Small < AllocationTable
				def initialize(*args)
					super
					@block_size = 1 << @ole.header.s_shift
					@io = @ole.sb_file
				end
			end
		end

		# like normal RangesIO, but Ole::Storage specific. the ranges are backed by an
		# AllocationTable, and can be resized. used for read/write to 2 streams:
		# 1. serialized dirent data
		# 2. sbat table data
		# 3. all dirents but through RangesIOMigrateable below
		#
		# Note that all internal access to first_block is through accessors, as it is sometimes
		# useful to redirect it.
		class RangesIOResizeable < RangesIO
			attr_reader   :bat
			attr_accessor :first_block
			def initialize bat, first_block, size=nil
				@bat = bat
				self.first_block = first_block
				super @bat.io, @bat.ranges(first_block, size)
			end

			def truncate size
				# note that old_blocks is != @ranges.length necessarily. i'm planning to write a
				# merge_ranges function that merges sequential ranges into one as an optimization.
				self.first_block = @bat.resize_chain first_block, size
				@ranges = @bat.ranges first_block, size
				@pos = @size if @pos > size

				# don't know if this is required, but we explicitly request our @io to grow if necessary
				# we never shrink it though. maybe this belongs in allocationtable, where smarter decisions
				# can be made.
				# maybe its ok to just seek out there later??
				max = @ranges.map { |pos, len| pos + len }.max || 0
				@io.truncate max if max > @io.size

				@size = size
			end
		end

		# like RangesIOResizeable, but Ole::Storage::Dirent specific. provides for migration
		# between bats based on size, and updating the dirent, instead of the ole copy back
		# on close.
		class RangesIOMigrateable < RangesIOResizeable
			attr_reader :dirent
			def initialize dirent
				@dirent = dirent
				super @dirent.ole.bat_for_size(@dirent.size), @dirent.first_block, @dirent.size
			end

			def truncate size
				bat = @dirent.ole.bat_for_size size
				if bat != @bat
					# bat migration needed! we need to backup some data. the amount of data
					# should be <= @ole.header.threshold, so we can just hold it all in one buffer.
					# backup this
					pos = @pos
					@pos = 0
					keep = read [@size, size].min
					# this does a normal truncate to 0, removing our presence from the old bat, and
					# rewrite the dirent's first_block
					super 0
					@bat = bat
					# just change the underlying io from right under everyone :)
					@io = bat.io
					# important to do this now, before the write. as the below write will always
					# migrate us back to sbat! this will now allocate us +size+ in the new bat.
					super
					@pos = 0
					write keep
					@pos = pos
				else
					super
				end
				# now just update the file
				@dirent.size = size
			end

			# forward this to the dirent
			def first_block
				@dirent.first_block
			end

			def first_block= val
				@dirent.first_block = val
			end
		end

		#
		# A class which wraps an ole directory entry. Can be either a directory
		# (<tt>Dirent#dir?</tt>) or a file (<tt>Dirent#file?</tt>)
		#
		# Most interaction with <tt>Ole::Storage</tt> is through this class.
		# The 2 most important functions are <tt>Dirent#children</tt>, and
		# <tt>Dirent#data</tt>.
		# 
		# was considering separate classes for dirs and files. some methods/attrs only
		# applicable to one or the other.
		class Dirent
			MEMBERS = [
				:name_utf16, :name_len, :type_id, :colour, :prev, :next, :child,
				:clsid, :flags, # dirs only
				:create_time_str, :modify_time_str, # files only
				:first_block, :size, :reserved
			]
			PACK = 'a64 S C C L3 a16 L a8 a8 L2 a4'
			SIZE = 128
			EPOCH = DateTime.parse '1601-01-01'
			TYPE_MAP = {
				# this is temporary
				0 => :empty,
				1 => :dir,
				2 => :file,
				5 => :root
			}
			COLOUR_MAP = {
				0 => :red,
				1 => :black
			}
			# used in the next / prev / child stuff to show that the tree ends here.
			# also used for first_block for directory.
			EOT = 0xffffffff
			# All +Dirent+ names are in UTF16, which we convert
			FROM_UTF16 = Iconv.new 'utf-8', 'utf-16le'
			TO_UTF16   = Iconv.new 'utf-16le', 'utf-8'

			include Enumerable

			attr_accessor :values

			# Dirent's should be created in 1 of 2 ways, either Dirent.new ole, [:dir/:file/:root],
			# or Dirent.load '... dirent data ...'
			# its a bit clunky, but thats how it is at the moment. you can assign to type, but
			# shouldn't.

			attr_accessor :idx
			# This returns all the children of this +Dirent+. It is filled in
			# when the tree structure is recreated.
			attr_accessor :children
			attr_reader :ole, :type, :create_time, :modify_time, :name
			def initialize ole, type
				@ole = ole
				# this isn't really good enough. need default values put in there.
				@values = [
					0.chr * 2, 2, 0, # will get overwritten
					1, EOT, EOT, EOT,
					0.chr * 16, 0, nil, nil,
					AllocationTable::EOC, 0, 0.chr * 4]
				# maybe check types here. 
				@type = type
				@create_time = @modify_time = nil
				@children = []
				if file?
					@create_time = Time.now
					@modify_time = Time.now
				end
			end

			def self.load ole, str
				# load should function without the need for the initializer.
				dirent = Dirent.allocate
				dirent.load ole, str
				dirent
			end

			def load ole, str
				@ole = ole
				@values = str.unpack PACK
				@name = FROM_UTF16.iconv name_utf16[0...name_len].sub(/\x00\x00$/, '')
				@type = TYPE_MAP[type_id] or raise "unknown type #{type_id.inspect}"
				if file?
					@create_time = Types.load_time create_time_str
					@modify_time = Types.load_time modify_time_str
				end
			end

			# only defined for files really. and the above children stuff is only for children.
			# maybe i should have some sort of File and Dir class, that subclass Dirents? a dirent
			# is just a data holder. 
			# this can be used for write support if the underlying io object was opened for writing.
			# maybe take a mode string argument, and do truncation, append etc stuff.
			def open
				return nil unless file?
				io = RangesIOMigrateable.new self
				if block_given?
					begin   yield io
					ensure; io.close
					end
				else io
				end
			end

			def read limit=nil
				open { |io| io.read limit }
			end

			def dir?
				# to count root as a dir.
				type != :file
			end

			def file?
				type == :file
			end

			def time
				# time is nil for streams, otherwise try to parse either of the time pairse (not
				# sure of their meaning - created / modified?)
				#@time ||= file? ? nil : (Dirent.parse_time(secs1, days1) || Dirent.parse_time(secs2, days2))
				create_time || modify_time
			end

			def each(&block)
				@children.each(&block)
			end
			
			def [] idx
				return children[idx] if Integer === idx
				# path style look up.
				# maybe take another arg to allow creation? or leave that to the filesystem
				# add on. 
				# not sure if '/' is a valid char in an Dirent#name, so no splitting etc at
				# this level.
				# also what about warning about multiple hits for the same name?
				children.find { |child| idx === child.name }
			end

			# solution for the above '/' thing for now.
			def / path
				self[path]
			end

			def to_tree
				if children and !children.empty?
					str = "- #{inspect}\n"
					children.each_with_index do |child, i|
						last = i == children.length - 1
						child.to_tree.split(/\n/).each_with_index do |line, j|
							str << "  #{last ? (j == 0 ? "\\" : ' ') : '|'}#{line}\n"
						end
					end
					str
				else "- #{inspect}\n"
				end
			end

			MEMBERS.each_with_index do |sym, i|
				define_method(sym) { @values[i] }
				define_method(sym.to_s + '=') { |val| @values[i] = val }
			end

			def to_a
				@values
			end

			# flattens the tree starting from here into +dirents+. note it modifies its argument.
			def flatten dirents=[]
				@idx = dirents.length
				dirents << self
				children.each { |child| child.flatten dirents }
				self.child = Dirent.flatten_helper children
				dirents
			end

			# i think making the tree structure optimized is actually more complex than this, and
			# requires some intelligent ordering of the children based on names, but as long as
			# it is valid its ok.
			# actually, i think its ok. gsf for example only outputs a singly-linked-list, where
			# prev is always EOT.
			def self.flatten_helper children
				return EOT if children.empty?
				i = children.length / 2
				this = children[i]
				this.prev, this.next = [(0...i), (i+1..-1)].map { |r| flatten_helper children[r] }
				this.idx
			end

			attr_accessor :name, :type
			def save
				tmp = TO_UTF16.iconv(name)
				tmp = tmp[0, 62] if tmp.length > 62
				tmp += 0.chr * 2
				self.name_len = tmp.length
				self.name_utf16 = tmp + 0.chr * (64 - tmp.length)
				begin
					self.type_id = TYPE_MAP.to_a.find { |id, name| @type == name }.first
				rescue
					raise "unknown type #{type.inspect}"
				end
				# for the case of files, it is assumed that that was handled already
				# note not dir?, so as not to override root's first_block
				self.first_block = Dirent::EOT if type == :dir
				if 0 #file?
					#self.create_time_str = ?? #Types.load_time create_time_str
					#self.modify_time_str = ?? #Types.load_time modify_time_str
				else
					self.create_time_str = 0.chr * 8
					self.modify_time_str = 0.chr * 8
				end
				@values.pack PACK
			end

			def inspect
				str = "#<Dirent:#{name.inspect}"
				# perhaps i should remove the data snippet. its not that useful anymore.
				if file?
					tmp = read 9
					data = tmp.length == 9 ? tmp[0, 5] + '...' : tmp
					str << " size=#{size}" +
						"#{time ? ' time=' + time.to_s.inspect : nil}" +
						" data=#{data.inspect}"
				else
					# there is some dir specific stuff. like clsid, flags.
				end
				str + '>'
			end

			# --------
			# and for creation of a dirent. don't like the name. is it a file or a directory?
			# assign to type later? io will be empty.
			def new_child type
				child = Dirent.new ole, type
				children << child
				yield child if block_given?
				child
			end

			def delete child
				# remove from our child array, so that on reflatten and re-creation of @dirents, it will be gone
				raise "#{child.inspect} not a child of #{self.inspect}" unless @children.delete child
				# free our blocks
				child.open { |io| io.truncate 0 }
			end

			def self.copy src, dst
				# copies the contents of src to dst. must be the same type. this will throw an
				# error on copying to root. maybe this will recurse too much for big documents??
				raise unless src.type == dst.type
				dst.name = src.name
				if src.dir?
					src.children.each do |src_child|
						dst.new_child(src_child.type) { |dst_child| Dirent.copy src_child, dst_child }
					end
				else
					src.open do |src_io|
						dst.open { |dst_io| IO.copy src_io, dst_io }
					end
				end
			end
		end
	end
end

if $0 == __FILE__
	puts Ole::Storage.open(ARGV[0]) { |ole| ole.root.to_tree }
end