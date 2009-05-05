require 'ole/types/property_set'

module Ole
	class Storage
		#
		# The MetaData class is designed to be high level interface to all the
		# underlying meta data stored within different sections, themselves within
		# different property set streams.
		#
		# With this class, you can simply get properties using their names, without
		# needing to know about the underlying guids, property ids etc.
		#
		# Example:
		#
		#   Ole::Storage.open('test.doc') { |ole| p ole.meta_data.doc_author }
		#
		# TODO:
		#
		# * add write support
		# * fix some of the missing type coercion (eg FileTime)
		# * maybe add back the ability to access individual property sets as a unit
		#   directly. ie <tt>ole.summary_information</tt>. Is this useful?
		# * full key support, for unknown keys, like
		#   <tt>ole.meta_data[myguid, myid]</tt>. probably needed for user-defined
		#   properties too.
		#
		class MetaData
			include Enumerable

			FILE_MAP = {
				Types::PropertySet::FMTID_SummaryInformation => "\005SummaryInformation",
				Types::PropertySet::FMTID_DocSummaryInfo => "\005DocumentSummaryInformation"
			}

			FORMAT_MAP = {
				'MSWordDoc' => :doc
			}

			CLSID_EXCEL97 = Types::Clsid.parse "{00020820-0000-0000-c000-000000000046}"
			CLSID_EXCEL95 = Types::Clsid.parse "{00020810-0000-0000-c000-000000000046}"
			CLSID_WORD97  = Types::Clsid.parse "{00020906-0000-0000-c000-000000000046}"
			CLSID_WORD95  = Types::Clsid.parse "{00020900-0000-0000-c000-000000000046}"

			CLSID_MAP = {
				CLSID_EXCEL97 => :xls,
				CLSID_EXCEL95 => :xls,
				CLSID_WORD97  => :doc,
				CLSID_WORD95  => :doc
			}

			MIME_TYPES = {
				:xls => 'application/vnd.ms-excel',
				:doc => 'application/msword',
				:ppt => 'application/vnd.ms-powerpoint',
				# not registered at IANA, but seems most common usage
				:msg => 'application/vnd.ms-outlook',
				# this is my default fallback option. also not registered at IANA.
				# file(1)'s default is application/msword, which is useless...
				nil  => 'application/x-ole-storage'
			}

			def initialize ole
				@ole = ole
			end

			# i'm thinking of making file_format and mime_type available through
			# #[], #each, and #to_h also, as calculated meta data (not assignable)

			def comp_obj
				return {} unless dirent = @ole.root["\001CompObj"]
				data = dirent.read
				# see - https://gnunet.org/svn/Extractor/doc/StarWrite_File_Format.html
				# compobj_version: 0x0001
				# byte_order: 0xffe
				# windows_version: 0x00000a03 (win31 apparently)
				# marker: 0xffffffff
				compobj_version, byte_order, windows_version, marker, clsid =
					data.unpack("vvVVa#{Types::Clsid::SIZE}")
				strings = []
				i = 28
				while i < data.length
					len = data[i, 4].unpack('V').first
					i += 4
					strings << data[i, len - 1]
					i += len
				end
				# in the unknown chunk, you usually see something like 'Word.Document.6'
				{:username => strings[0], :file_format => strings[1], :unknown => strings[2..-1]}
			end
			private :comp_obj

			def file_format
				comp_obj[:file_format]
			end

			def mime_type
				# based on the CompObj stream contents
				type = FORMAT_MAP[file_format]
				return MIME_TYPES[type] if type

				# based on the root clsid
				type = CLSID_MAP[Types::Clsid.load(@ole.root.clsid)]
				return MIME_TYPES[type] if type

				# fallback to heuristics
				has_file = Hash[*@ole.root.children.map { |d| [d.name.downcase, true] }.flatten]
				return MIME_TYPES[:msg] if has_file['__nameid_version1.0'] or has_file['__properties_version1.0']
				return MIME_TYPES[:doc] if has_file['worddocument'] or has_file['document']
				return MIME_TYPES[:xls] if has_file['workbook'] or has_file['book']

				MIME_TYPES[nil]
			end

			def [] key
				pair = Types::PropertySet::PROPERTY_MAP[key.to_s] or return nil
				file = FILE_MAP[pair.first] or return nil
				dirent = @ole.root[file] or return nil
				dirent.open { |io| return Types::PropertySet.new(io)[key] }
			end

			def []= key, value
				raise NotImplementedError, 'meta data writes not implemented'
			end

			def each(&block)
				FILE_MAP.values.each do |file|
					dirent = @ole.root[file] or next
					dirent.open { |io| Types::PropertySet.new(io).each(&block) }
				end
			end

			def to_h
				inject({}) { |hash, (name, value)| hash.update name.to_sym => value }
			end

			def method_missing name, *args, &block
				return super unless args.empty?
				pair = Types::PropertySet::PROPERTY_MAP[name.to_s] or return super
				self[name]
			end
		end

		def meta_data
			@meta_data ||= MetaData.new(self)
		end
	end
end

