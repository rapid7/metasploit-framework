require 'tempfile'

require 'ole/base'
require 'ole/types'
require 'ole/ranges_io'

module Ole # :nodoc:
	#
	# This class is the primary way the user interacts with an OLE storage file.
	#
	# = TODO
	#
	# * the custom header cruft for Header and Dirent needs some love.
	# * i have a number of classes doing load/save combos: Header, AllocationTable, Dirent,
	#   and, in a manner of speaking, but arguably different, Storage itself.
	#   they have differing api's which would be nice to rethink.
	#   AllocationTable::Big must be created aot now, as it is used for all subsequent reads.
	#
	class Storage
		# thrown for any bogus OLE file errors.
		class FormatError < StandardError # :nodoc:
		end

		VERSION = '1.2.8.2'

		# options used at creation time
		attr_reader :params
		# The top of the ole tree structure
		attr_reader :root
		# The tree structure in its original flattened form. only valid after #load, or #flush.
		attr_reader :dirents
		# The underlying io object to/from which the ole object is serialized, whether we
		# should close it, and whether it is writeable
		attr_reader :io, :close_parent, :writeable
		# Low level internals, you probably shouldn't need to mess with these
		attr_reader :header, :bbat, :sbat, :sb_file

		# +arg+ should be either a filename, or an +IO+ object, and needs to be seekable.
		# +mode+ is optional, and should be a regular mode string.
		def initialize arg, mode=nil, params={}
			params, mode = mode, nil if Hash === mode
			params = {:update_timestamps => true}.merge(params)
			@params = params
	
			# get the io object
			@close_parent, @io = if String === arg
				mode ||= 'rb'
				[true, open(arg, mode)]
			else
				raise ArgumentError, 'unable to specify mode string with io object' if mode
				[false, arg]
			end
			# do we have this file opened for writing? don't know of a better way to tell
			# (unless we parse the mode string in the open case)
			# hmmm, note that in ruby 1.9 this doesn't work anymore. which is all the more
			# reason to use mode string parsing when available, and fall back to something like
			# io.writeable? otherwise.
			@writeable = begin
				if mode
					IO::Mode.new(mode).writeable?
				else
					@io.flush
					# this is for the benefit of ruby-1.9
					@io.syswrite('') if @io.respond_to?(:syswrite)
					true
				end
			rescue IOError
				false
			end
			# silence undefined warning in clear
			@sb_file = nil
			# if the io object has data, we should load it, otherwise start afresh
			# this should be based on the mode string rather.
			@io.size > 0 ? load : clear
		end

		# somewhat similar to File.open, the open class method allows a block form where
		# the Ole::Storage object is automatically closed on completion of the block.
		def self.open arg, mode=nil, params={}
			ole = new arg, mode, params
			if block_given?
				begin   yield ole
				ensure; ole.close
				end
			else ole
			end
		end

		# load document from file.
		#
		# TODO: implement various allocationtable checks, maybe as a AllocationTable#fsck function :)
		#
		# 1. reterminate any chain not ending in EOC.
		#    compare file size with actually allocated blocks per file.
		# 2. pass through all chain heads looking for collisions, and making sure nothing points to them
		#    (ie they are really heads). in both sbat and mbat
		# 3. we know the locations of the bbat data, and mbat data. ensure that there are placeholder blocks
		#    in the bat for them.
		# 4. maybe a check of excess data. if there is data outside the bbat.truncate.length + 1 * block_size,
		#    (eg what is used for truncate in #flush), then maybe add some sort of message about that. it
		#    will be automatically thrown away at close time.
		def load
			# we always read 512 for the header block. if the block size ends up being different,
			# what happens to the 109 fat entries. are there more/less entries?
			@io.rewind
			header_block = @io.read 512
			@header = Header.new header_block

			# create an empty bbat.
			@bbat = AllocationTable::Big.new self
			bbat_chain = header_block[Header::SIZE..-1].unpack 'V*'
			mbat_block = @header.mbat_start
			@header.num_mbat.times do
				blocks = @bbat.read([mbat_block]).unpack 'V*'
				mbat_block = blocks.pop
				bbat_chain += blocks
			end
			# am i using num_bat in the right way?
			@bbat.load @bbat.read(bbat_chain[0, @header.num_bat])
	
			# get block chain for directories, read it, then split it into chunks and load the
			# directory entries. semantics changed - used to cut at first dir where dir.type == 0
			@dirents = @bbat.read(@header.dirent_start).to_enum(:each_chunk, Dirent::SIZE).
				map { |str| Dirent.new self, str }.reject { |d| d.type_id == 0 }

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
					raise FormatError, "directory #{d.inspect} used twice" if d.idx
					d.idx = idx
					to_tree(d.prev) + [d] + to_tree(d.next)
				end
			end

			@root = @dirents.to_tree.first
			Log.warn "root name was #{@root.name.inspect}" unless @root.name == 'Root Entry'
			unused = @dirents.reject(&:idx).length
			Log.warn "#{unused} unused directories" if unused > 0

			# FIXME i don't currently use @header.num_sbat which i should
			# hmm. nor do i write it. it means what exactly again?
			# which mode to use here?
			@sb_file = RangesIOResizeable.new @bbat, :first_block => @root.first_block, :size => @root.size
			@sbat = AllocationTable::Small.new self
			@sbat.load @bbat.read(@header.sbat_start)
		end

		def close
			@sb_file.close
			flush if @writeable
			@io.close if @close_parent
		end

		# the flush method is the main "save" method. all file contents are always
		# written directly to the file by the RangesIO objects, all this method does
		# is write out all the file meta data - dirents, allocation tables, file header
		# etc.
		#
		# maybe add an option to zero the padding, and any remaining avail blocks in the
		# allocation table.
		#
		# TODO: long and overly complex. simplify and test better. eg, perhaps move serialization
		# of bbat to AllocationTable::Big. 
		def flush
			# update root dirent, and flatten dirent tree
			@root.name = 'Root Entry'
			@root.first_block = @sb_file.first_block
			@root.size = @sb_file.size
			@dirents = @root.flatten

			# serialize the dirents using the bbat
			RangesIOResizeable.open @bbat, 'w', :first_block => @header.dirent_start do |io|
				@dirents.each { |dirent| io.write dirent.to_s }
				padding = (io.size / @bbat.block_size.to_f).ceil * @bbat.block_size - io.size
				io.write 0.chr * padding
				@header.dirent_start = io.first_block
			end

			# serialize the sbat
			# perhaps the blocks used by the sbat should be marked with BAT?
			RangesIOResizeable.open @bbat, 'w', :first_block => @header.sbat_start do |io|
				io.write @sbat.to_s
				@header.sbat_start = io.first_block
				@header.num_sbat = @bbat.chain(@header.sbat_start).length
			end

			# create RangesIOResizeable hooked up to the bbat. use that to claim bbat blocks using
			# truncate. then when its time to write, convert that chain and some chunk of blocks at
			# the end, into META_BAT blocks. write out the chain, and those meta bat blocks, and its
			# done.
			# this is perhaps not good, as we reclaim all bat blocks here, which
			# may include the sbat we just wrote. FIXME
			@bbat.map! do |b|
				b == AllocationTable::BAT || b == AllocationTable::META_BAT ? AllocationTable::AVAIL : b
			end
	
			# currently we use a loop. this could be better, but basically,
			# the act of writing out the bat, itself requires blocks which get
			# recorded in the bat.
			#
			# i'm sure that there'd be some simpler closed form solution to this. solve
			# recursive func:
			#
			#   num_mbat_blocks = ceil(max((mbat_len - 109) * 4 / block_size, 0))
			#   bbat_len = initial_bbat_len + num_mbat_blocks
			#   mbat_len = ceil(bbat_len * 4 / block_size)
			#
			# the actual bbat allocation table is itself stored throughout the file, and that chain
			# is stored in the initial blocks, and the mbat blocks.
			num_mbat_blocks = 0
			io = RangesIOResizeable.new @bbat, 'w', :first_block => AllocationTable::EOC
			# truncate now, so that we can simplify size calcs - the mbat blocks will be appended in a
			# contiguous chunk at the end.
			# hmmm, i think this truncate should be matched with a truncate of the underlying io. if you
			# delete a lot of stuff, and free up trailing blocks, the file size never shrinks. this can
			# be fixed easily, add an io truncate
			@bbat.truncate!
			before = @io.size
			@io.truncate @bbat.block_size * (@bbat.length + 1)
			while true
				# get total bbat size. equivalent to @bbat.to_s.length, but for the factoring in of
				# the mbat blocks. we can't just add the mbat blocks directly to the bbat, as as this iteration
				# progresses, more blocks may be needed for the bat itself (if there are no more gaps), and the
				# mbat must remain contiguous.
				bbat_data_len = ((@bbat.length + num_mbat_blocks) * 4 / @bbat.block_size.to_f).ceil * @bbat.block_size
				# now storing the excess mbat blocks also increases the size of the bbat:
				new_num_mbat_blocks = ([bbat_data_len / @bbat.block_size - 109, 0].max * 4 / (@bbat.block_size.to_f - 4)).ceil
				if new_num_mbat_blocks != num_mbat_blocks
					# need more space for the mbat.
					num_mbat_blocks = new_num_mbat_blocks
				elsif io.size != bbat_data_len
					# need more space for the bat
					# this may grow the bbat, depending on existing available blocks
					io.truncate bbat_data_len
				else
					break
				end
			end

			# now extract the info we want:
			ranges = io.ranges
			bbat_chain = @bbat.chain io.first_block
			io.close
			bbat_chain.each { |b| @bbat[b] = AllocationTable::BAT }
			# tack on the mbat stuff
			@header.num_bat = bbat_chain.length
			mbat_blocks = (0...num_mbat_blocks).map do
				block = @bbat.free_block
				@bbat[block] = AllocationTable::META_BAT
				block
			end
			@header.mbat_start = mbat_blocks.first || AllocationTable::EOC

			# now finally write the bbat, using a not resizable io.
			# the mode here will be 'r', which allows write atm. 
			RangesIO.open(@io, :ranges => ranges) { |f| f.write @bbat.to_s }

			# this is the mbat. pad it out.
			bbat_chain += [AllocationTable::AVAIL] * [109 - bbat_chain.length, 0].max
			@header.num_mbat = num_mbat_blocks
			if num_mbat_blocks != 0
				# write out the mbat blocks now. first of all, where are they going to be?
				mbat_data = bbat_chain[109..-1]
				# expand the mbat_data to include the linked list forward pointers.
				mbat_data = mbat_data.to_enum(:each_slice, @bbat.block_size / 4 - 1).to_a.
					zip(mbat_blocks[1..-1] + [nil]).map { |a, b| b ? a + [b] : a }
				# pad out the last one.
				mbat_data.last.push(*([AllocationTable::AVAIL] * (@bbat.block_size / 4 - mbat_data.last.length)))
				RangesIO.open @io, :ranges => @bbat.ranges(mbat_blocks) do |f|
					f.write mbat_data.flatten.pack('V*')
				end
			end

			# now seek back and write the header out
			@io.seek 0
			@io.write @header.to_s + bbat_chain[0, 109].pack('V*')
			@io.flush
		end

		def clear
			# initialize to equivalent of loading an empty ole document.
			Log.warn 'creating new ole storage object on non-writable io' unless @writeable
			@header = Header.new
			@bbat = AllocationTable::Big.new self
			@root = Dirent.new self, :type => :root, :name => 'Root Entry'
			@dirents = [@root]
			@root.idx = 0
			@sb_file.close if @sb_file
			@sb_file = RangesIOResizeable.new @bbat, :first_block => AllocationTable::EOC
			@sbat = AllocationTable::Small.new self
			# throw everything else the hell away
			@io.truncate 0
		end

		# could be useful with mis-behaving ole documents. or to just clean them up.
		def repack temp=:file
			case temp
			when :file
				Tempfile.open 'ole-repack' do |io|
					io.binmode
					repack_using_io io
				end
			when :mem;  StringIO.open('', &method(:repack_using_io))
			else raise ArgumentError, "unknown temp backing #{temp.inspect}"
			end
		end

		def repack_using_io temp_io
			@io.rewind
			IO.copy @io, temp_io
			clear
			Storage.open temp_io, nil, @params do |temp_ole|
				#temp_ole.root.type = :dir
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

		#
		# A class which wraps the ole header
		#
		# Header.new can be both used to load from a string, or to create from
		# defaults. Serialization is accomplished with the #to_s method.
		#
		class Header < Struct.new(
				:magic, :clsid, :minor_ver, :major_ver, :byte_order, :b_shift, :s_shift,
				:reserved, :csectdir, :num_bat, :dirent_start, :transacting_signature, :threshold,
				:sbat_start, :num_sbat, :mbat_start, :num_mbat
			)
			PACK = 'a8 a16 v2 a2 v2 a6 V3 a4 V5'
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

			def initialize values=DEFAULT
				values = values.unpack(PACK) if String === values
				super(*values)
				validate!
			end

			def to_s
				to_a.pack PACK
			end

			def validate!
				raise FormatError, "OLE2 signature is invalid" unless magic == MAGIC
				if num_bat == 0 or # is that valid for a completely empty file?
					 # not sure about this one. basically to do max possible bat given size of mbat
					 num_bat > 109 && num_bat > 109 + num_mbat * (1 << b_shift - 2) or
					 # shouldn't need to use the mbat as there is enough space in the header block
					 num_bat < 109 && num_mbat != 0 or
					 # given the size of the header is 76, if b_shift <= 6, blocks address the header.
					 s_shift > b_shift or b_shift <= 6 or b_shift >= 31 or
					 # we only handle little endian
					 byte_order != "\xfe\xff"
					raise FormatError, "not valid OLE2 structured storage file"
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
		# AllocationTable.new is used to create an empty table. It can parse a string
		# with the #load method. Serialization is accomplished with the #to_s method.
		#
		class AllocationTable < Array
			# a free block (I don't currently leave any blocks free), although I do pad out
			# the allocation table with AVAIL to the block size.
			AVAIL		 = 0xffffffff
			EOC			 = 0xfffffffe # end of a chain
			# these blocks are used for storing the allocation table chains
			BAT			 = 0xfffffffd
			META_BAT = 0xfffffffc

			attr_reader :ole, :io, :block_size
			def initialize ole
				@ole = ole
				@sparse = true
				super()
			end

			def load data
				replace data.unpack('V*')
			end

			def truncate
				# this strips trailing AVAILs. come to think of it, this has the potential to break
				# bogus ole. if you terminate using AVAIL instead of EOC, like I did before. but that is
				# very broken. however, if a chain ends with AVAIL, it should probably be fixed to EOC
				# at load time.
				temp = reverse
				not_avail = temp.find { |b| b != AVAIL } and temp = temp[temp.index(not_avail)..-1]
				temp.reverse
			end

			def truncate!
				replace truncate
			end

			def to_s
				table = truncate
				# pad it out some
				num = @ole.bbat.block_size / 4
				# do you really use AVAIL? they probably extend past end of file, and may shortly
				# be used for the bat. not really good.
				table += [AVAIL] * (num - (table.length % num)) if (table.length % num) != 0
				table.pack 'V*'
			end

			# rewrote this to be non-recursive as it broke on a large attachment
			# chain with a stack error
			def chain idx
				a = []
				until idx >= META_BAT
					raise FormatError, "broken allocationtable chain" if idx < 0 || idx > length
					a << idx
					idx = self[idx]
				end
				Log.warn "invalid chain terminator #{idx}" unless idx == EOC
				a
			end
			
			# Turn a chain (an array given by +chain+) of blocks (optionally
			# truncated to +size+) into an array of arrays describing the stretches of
			# bytes in the file that it belongs to.
			#
			# The blocks are Big or Small blocks depending on the table type.
			def blocks_to_ranges chain, size=nil
				# truncate the chain if required
				chain = chain[0...(size.to_f / block_size).ceil] if size
				# convert chain to ranges of the block size
				ranges = chain.map { |i| [block_size * i, block_size] }
				# truncate final range if required
				ranges.last[1] -= (ranges.length * block_size - size) if ranges.last and size
				ranges
			end

			def ranges chain, size=nil
				chain = self.chain(chain) unless Array === chain
				blocks_to_ranges chain, size
			end

			# quick shortcut. chain can be either a head (in which case the table is used to
			# turn it into a chain), or a chain. it is converted to ranges, then to rangesio.
			def open chain, size=nil, &block
				RangesIO.open @io, :ranges => ranges(chain, size), &block
			end

			def read chain, size=nil
				open chain, size, &:read
			end

			# catch any method that may add an AVAIL somewhere in the middle, thus invalidating
			# the @sparse speedup for free_block. annoying using eval, but define_method won't
			# work for this.
			# FIXME
			[:map!, :collect!].each do |name|
				eval <<-END
					def #{name}(*args, &block)
						@sparse = true
						super
					end
				END
			end

			def []= idx, val
				@sparse = true if val == AVAIL
				super
			end

			def free_block
				if @sparse
					i = index(AVAIL) and return i
				end
				@sparse = false
				push AVAIL
				length - 1
			end

			# must return first_block. modifies +blocks+ in place
			def resize_chain blocks, size
				new_num_blocks = (size / block_size.to_f).ceil
				old_num_blocks = blocks.length
				if new_num_blocks < old_num_blocks
					# de-allocate some of our old blocks. TODO maybe zero them out in the file???
					(new_num_blocks...old_num_blocks).each { |i| self[blocks[i]] = AVAIL }
					self[blocks[new_num_blocks-1]] = EOC if new_num_blocks > 0
					blocks.slice! new_num_blocks..-1
				elsif new_num_blocks > old_num_blocks
					# need some more blocks.
					last_block = blocks.last
					(new_num_blocks - old_num_blocks).times do
						block = free_block
						# connect the chain. handle corner case of blocks being [] initially
						self[last_block] = block if last_block
						blocks << block
						last_block = block
						self[last_block] = EOC
					end
				end
				# update ranges, and return that also now
				blocks
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
			def initialize bat, mode='r', params={}
				mode, params = 'r', mode if Hash === mode
				first_block, size = params.values_at :first_block, :size
				raise ArgumentError, 'must specify first_block' unless first_block
				@bat = bat
				self.first_block = first_block
				# we now cache the blocks chain, for faster resizing.
				@blocks = @bat.chain first_block
				super @bat.io, mode, :ranges => @bat.ranges(@blocks, size)
			end

			def truncate size
				# note that old_blocks is != @ranges.length necessarily. i'm planning to write a
				# merge_ranges function that merges sequential ranges into one as an optimization.
				@bat.resize_chain @blocks, size
				@ranges = @bat.ranges @blocks, size
				@pos = @size if @pos > size
				self.first_block = @blocks.empty? ? AllocationTable::EOC : @blocks.first

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
		# between bats based on size, and updating the dirent.
		class RangesIOMigrateable < RangesIOResizeable
			attr_reader :dirent
			def initialize dirent, mode='r'
				@dirent = dirent
				super @dirent.ole.bat_for_size(@dirent.size), mode,
					:first_block => @dirent.first_block, :size => @dirent.size
			end

			def truncate size
				bat = @dirent.ole.bat_for_size size
				if bat.class != @bat.class
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
		#
		# As with the other classes, #to_s performs the serialization.
		#
		class Dirent < Struct.new(
				:name_utf16, :name_len, :type_id, :colour, :prev, :next, :child,
				:clsid, :flags, # dirs only
				:create_time_str, :modify_time_str, # files only
				:first_block, :size, :reserved
			)
			include RecursivelyEnumerable

			PACK = 'a64 v C C V3 a16 V a8 a8 V2 a4'
			SIZE = 128
			TYPE_MAP = {
				# this is temporary
				0 => :empty,
				1 => :dir,
				2 => :file,
				5 => :root
			}
			# something to do with the fact that the tree is supposed to be red-black
			COLOUR_MAP = {
				0 => :red,
				1 => :black
			}
			# used in the next / prev / child stuff to show that the tree ends here.
			# also used for first_block for directory.
			EOT = 0xffffffff
			DEFAULT = [
				0.chr * 2, 2, 0, # will get overwritten
				1, EOT, EOT, EOT,
				0.chr * 16, 0, nil, nil,
				AllocationTable::EOC, 0, 0.chr * 4
			]

			# i think its just used by the tree building
			attr_accessor :idx
			# This returns all the children of this +Dirent+. It is filled in
			# when the tree structure is recreated.
			attr_accessor :children
			attr_accessor :name
			attr_reader :ole, :type, :create_time, :modify_time
			def initialize ole, values=DEFAULT, params={}
				@ole = ole				
				values, params = DEFAULT, values if Hash === values
				values = values.unpack(PACK) if String === values
				super(*values)

				# extra parsing from the actual struct values
				@name = params[:name] || Types::Variant.load(Types::VT_LPWSTR, name_utf16[0...name_len])
				@type = if params[:type]
					unless TYPE_MAP.values.include?(params[:type])
						raise ArgumentError, "unknown type #{params[:type].inspect}"
					end
					params[:type]
				else
					TYPE_MAP[type_id] or raise FormatError, "unknown type_id #{type_id.inspect}"
				end

				# further extra type specific stuff
				if file?
					default_time = @ole.params[:update_timestamps] ? Time.now : nil
					@create_time ||= default_time
					@modify_time ||= default_time
					@create_time = Types::Variant.load(Types::VT_FILETIME, create_time_str) if create_time_str
					@modify_time = Types::Variant.load(Types::VT_FILETIME, create_time_str) if modify_time_str
					@children = nil
				else
					@create_time = nil
					@modify_time = nil
					self.size = 0 unless @type == :root
					@children = []
				end
				
				# to silence warnings. used for tree building at load time
				# only.
				@idx = nil
			end

			def open mode='r'
				raise Errno::EISDIR unless file?
				io = RangesIOMigrateable.new self, mode
				# TODO work on the mode string stuff a bit more.
				# maybe let the io object know about the mode, so it can refuse
				# to work for read/write appropriately. maybe redefine all unusable
				# methods using singleton class to throw errors.
				# for now, i just want to implement truncation on use of 'w'. later,
				# i need to do 'a' etc.
				case mode
				when 'r', 'r+'
					# as i don't enforce reading/writing, nothing changes here. kind of
					# need to enforce tt if i want modify times to work better.
					@modify_time = Time.now if mode == 'r+'
				when 'w'
					@modify_time = Time.now
				#	io.truncate 0
				#else
				#	raise NotImplementedError, "unsupported mode - #{mode.inspect}"
				end
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

			def file?
				type == :file
			end

			def dir?
				# to count root as a dir.
				!file?
			end

			# maybe need some options regarding case sensitivity.
			def / name
				children.find { |child| name === child.name }
			end

			def [] idx
				if String === idx
					#warn 'String form of Dirent#[] is deprecated'
					self / idx
				else
					super
				end
			end

			# move to ruby-msg. and remove from here
			def time
				#warn 'Dirent#time is deprecated'
				create_time || modify_time
			end

			def each_child(&block)
				@children.each(&block)
			end

			# flattens the tree starting from here into +dirents+. note it modifies its argument.
			def flatten dirents=[]
				@idx = dirents.length
				dirents << self
				if file?
					self.prev = self.next = self.child = EOT
				else
					children.each { |child| child.flatten dirents } 
					self.child = Dirent.flatten_helper children
				end
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

			def to_s
				tmp = Types::Variant.dump(Types::VT_LPWSTR, name)
				tmp = tmp[0, 62] if tmp.length > 62
				tmp += 0.chr * 2
				self.name_len = tmp.length
				self.name_utf16 = tmp + 0.chr * (64 - tmp.length)
				# type_id can perhaps be set in the initializer, as its read only now.
				self.type_id = TYPE_MAP.to_a.find { |id, name| @type == name }.first
				# for the case of files, it is assumed that that was handled already
				# note not dir?, so as not to override root's first_block
				self.first_block = Dirent::EOT if type == :dir
				if file?
					# this is messed up. it changes the time stamps regardless of whether the file
					# was actually touched. instead, any open call with a writeable mode, should update
					# the modify time. create time would be set in new.
					if @ole.params[:update_timestamps]
						self.create_time_str = Types::Variant.dump Types::VT_FILETIME, @create_time
						self.modify_time_str = Types::Variant.dump Types::VT_FILETIME, @modify_time
					end
				else
					self.create_time_str = 0.chr * 8
					self.modify_time_str = 0.chr * 8
				end
				to_a.pack PACK
			end

			def inspect
				str = "#<Dirent:#{name.inspect}"
				# perhaps i should remove the data snippet. its not that useful anymore.
				# there is also some dir specific stuff. like clsid, flags, that i should
				# probably include
				if file?
					tmp = read 9
					data = tmp.length == 9 ? tmp[0, 5] + '...' : tmp
					str << " size=#{size}" +
						"#{modify_time ? ' modify_time=' + modify_time.to_s.inspect : nil}" +
						" data=#{data.inspect}"
				end
				str + '>'
			end

			def delete child
				# remove from our child array, so that on reflatten and re-creation of @dirents, it will be gone
				raise ArgumentError, "#{child.inspect} not a child of #{self.inspect}" unless @children.delete child
				# free our blocks
				child.open { |io| io.truncate 0 }
			end

			def self.copy src, dst
				# copies the contents of src to dst. must be the same type. this will throw an
				# error on copying to root. maybe this will recurse too much for big documents??
				raise ArgumentError, 'differing types' if src.file? and !dst.file?
				dst.name = src.name
				if src.dir?
					src.children.each do |src_child|
						dst_child = Dirent.new dst.ole, :type => src_child.type
						dst.children << dst_child
						Dirent.copy src_child, dst_child
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

