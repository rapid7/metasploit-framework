##
# $Id$
##

module Rex
module Zip

#
# This represents an entire archive.
#
class Archive
	attr_reader :entries

	def initialize(compmeth=CM_DEFLATE)
		@compmeth = compmeth
		@entries = []
	end


	def add_file(fname, fdata=nil, xtra=nil, comment=nil)
		if (not fdata)
			begin
				st = File.stat(fname)
			rescue
				return nil
			end

			ts = st.mtime
			if (st.directory?)
				attrs = EFA_ISDIR
				fname += '/'
			else
				f = File.open(fname, 'rb')
				fdata = f.read(f.stat.size)
				f.close
			end
		end

		@entries << Entry.new(fname, fdata, @compmeth, ts, attrs, xtra, comment)
	end


	def set_comment(comment)
		@comment = comment
	end


	def save_to(fname)
		f = File.open(fname, 'wb')
		f.write(pack)
		f.close
	end


	def pack
		ret = ''

		# save the offests
		offsets = []

		# file 1 .. file n
		@entries.each { |ent|
			offsets << ret.length
			ret << ent.pack
		}

		# archive decryption header (unsupported)
		# archive extra data record (unsupported)

		# central directory
		cfd_offset = ret.length
		idx = 0
		@entries.each { |ent|
			cfd = CentralDir.new(ent, offsets[idx])
			ret << cfd.pack
			idx += 1
		}

		# zip64 end of central dir record (unsupported)
		# zip64 end of central dir locator (unsupported)

		# end of central directory record
		cur_offset = ret.length - cfd_offset
		ret << CentralDirEnd.new(@entries.length, cur_offset, cfd_offset, @comment).pack

		ret
	end

end

class Jar < Archive
	attr_accessor :manifest

	def build_manifest(opts={})
		main_class = opts[:main_class] || nil
		skip = opts[:skip] || /^$/

		@manifest = ''

		@manifest = "Main-Class: #{main_class}\n\n" if main_class
		@entries.each { |e|
			next if e.name =~ skip
			@manifest << "Name: #{e.name}\n\n"
		}
		add_file("META-INF/", '')
		add_file("META-INF/MANIFEST.MF", @manifest)
	end

	def to_s
		pack
	end

	def length
		pack.length
	end
end

end
end
