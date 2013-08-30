#!/usr/bin/env ruby
# LCABruby version 0.1
# LCABruby is a small ruby script that creates an uncompressed MS Cabinet File (.cab) from a set of input files. LCABruby is a ruby port of LCABperl.
# LCABruby is based on software from LCAB. LCAB is a small program for linux that creates an uncompressed MS Cabinet File from a set of input files. LCAB was formerly known as cablinux.
#		                                                                                                                                                                                                                                                                                                                        For more information about LCAB please visit: http://lcab.move-to-cork.com/ (seems down)
# New (temporary) LCAB maintainer: http://ohnobinki.u.ohnopublishing.net/~ohnobinki/lcab/
#
#		http://packages.ubuntu.com/search?keywords=lcab
#
# Please note that LCABperl is licensed under GPL :

##  Copyright 2003 Rien Croonenborghs, Yoshinori Takesako
##
##    This file is part of lcabperl.pl.
##    lcabperl.pl is free software; you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation; either version 2 of the License, or
##    (at your option) any later version.
##    lcabperl.pl is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##    You should have received a copy of the GNU General Public License
##    along with lcabperl; if not, write to the Free Software
##    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Modified to accept files programatically rather than from the FileSystem.

require 'logger'

module Lcab

	## CONSTANTS
	BLOCKSIZE  = 32768
	FILEOFFSET = 44 #(0x2c)

	module FileHelper

		## get filespecs
		## filesize
		## last modified time
		def get_file_specs(file, path = nil)
			rh_file = { 'path' => path ? path : file }
			file_stat = File.stat(file)
			rh_file['size'] = file_stat.size
			rh_file['mtime'] = file_stat.mtime
			return rh_file
		end

		## get total filesize
		def get_total_file_size(file_spec_list)
			sum = 0;
			file_spec_list.each { |file_spec| sum += file_spec['size'] }
			return sum;
		end

		## get the list with input files
		#@ loop thru arguments:
		## if arg is file, add
		## if arg is dir -> loop recursive trhu dir
		def get_file_list(files)
			file_list = []
			files.each do |file|
				if File.file?(file)
					file_list << get_file_specs(file)
				elsif File.directory?(file)
					get_dir_list(file_list, file)
				else
					logger.warn "file '#{file}' not found"
				end
			end
			return file_list
		end

		private

		def get_dir_list(file_list, path)
			#    my ($ralist,$path) = @_;
			#    foreach my $f( <$path/*> )
			#    {
			#      if( -d $f )
			#      {
			#        GetDirList( $ralist, $f );
			#      }
			#      elsif( -f $f )
			#      {
			#        my %newfile = ( 'path' => $f );
			#        GetFileSpecs( \%newfile );
			#        $$ralist[ $#$ralist+1 ] = \%newfile;
			#      }
			#    }
			path = path[0..-2] if path[-1] == '/'[0]
			(Dir.entries(path) - ['.', '..']).each do |file|
				# NOTE: do not expand the path as we don't want
				# absolute paths within the archive unless explicitly
				# requested ! TODO:
				# ruby $PATH_TO/lcabruby.rb -o my.cab folder - includes 'folder' within cap
				# ruby $PATH_TO/lcabruby.rb -o my.cab ../folder - includes 'xx/folder' within cap
				#file = File.expand_path(file, path)
				file = path + '/' + file
				if File.directory?(file)
					get_dir_list(file_list, file)
				elsif File.file?(file)
					file_list << get_file_specs(file)
				else
					logger.warn "file '#{file}' not found within path '#{path}'"
				end
			end
		end

		## strip the path
		def strip_path(path)
			#$path = substr( $path, rindex($path,$LINSEP)+1 );
			if path and path.rindex('/')
				path[(path.rindex('/') + 1)..-1]
			else
				return path
			end
		end

		## make win path
		def make_win_path(path)
			#$path =~ s/$LINSEP/$WINSEP/g;
			path.gsub('/', '\\')
		end

		## make cabinet file date from certain file
		def make_cab_file_date(file_spec)
			#my $seconds = $rhfile->{'mtime'};
			#my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($seconds);
			#my $res = ( (($year+1900) - 1980 ) << 9 ) + ( ($mon+1) << 5 ) + $mday;
			mtime = file_spec['mtime']
			( (mtime.year - 1980 ) << 9 ) + ( mtime.month << 5 ) + mtime.mday
		end

		## make cabinet file date
		def make_cab_file_time(file_spec)
			#my $seconds = $rhfile->{'mtime'};
			#my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($seconds);
			#my $res = ( $hour << 11 ) + ( $min << 5 ) + ( $sec / 2 );
			mtime = file_spec['mtime']
			( mtime.hour << 11 ) + ( mtime.min << 5 ) + ( mtime.sec / 2 )
		end

	end

	## settings

	CabHeader  = {	'sig' => "MSCF",		## signature
	                  'res1' => 0,
	                  'size' => 0,			## total size of cab file
	                  'res2' => 0,
	                  'offset' => FILEOFFSET,	        ## offset of files
	                  'res3' => 0,
	                  'vmaj' => 1,			## 1
	                  'vmin' => 3,			## 3
	                  'numfolders' => 1,		## 0 (not supported)
	                  'numfiles' => 0,		## number of files in cab file
	                  'flags' => 0,
	                  'setid' => 1234,		## set ID (not supported)
	                  'cabid' => 0		};	## cab ID (not supported)
	CabFolder  = {	'offset' => 0,			## offset of data
	                  'numblocks' => 0,   		## number of blocks
	                  'typecmp' => 0		};	## 0 = no compression

	class CabFile
		include FileHelper

		TRACE = false

		attr_accessor :logger

		def initialize
			@logger = Logger.new(STDOUT)
			@logger.level = Logger::WARN
			@logger.datetime_format = "%H:%M:%S"
		end

		def file_list=(paths)
			paths = [ paths ] unless paths.is_a?(Array)
			@file_list = get_file_list(paths)
			logger.debug "file_list = #{@file_list.inspect}"
			#
			@cab_header = {}.update Lcab::CabHeader
			@cab_folder = {}.update Lcab::CabFolder
			#
			@cab_blocks =[]
			@cab_files = []
			#
			## 1.1 number of files
			@cab_header['numfiles'] = num_files
			## 2.1 number of blocks
			@cab_folder['numblocks'] = num_blocks
			@cab_folder['offset'] = Lcab::FILEOFFSET + data_offset
			#
			## 1.3 header size part 2
			@cab_header['size'] = header_size
			#
			@cab_files = cab_files
		end

		# Data files is an array
		# containing :filename :data
		def datafile_list=(datafiles)
			@file_list = []
			datafiles.each do |f|
				file = { 'path' => f[:filename],
				         'size' => f[:data].size,
				         'mtime' => Time.now,
						 'data' => f[:data]
				}
				@file_list << file
			end

			logger.debug "file_list = #{@file_list.inspect}"
			#
			@cab_header = {}.update Lcab::CabHeader
			@cab_folder = {}.update Lcab::CabFolder
			#
			@cab_blocks =[]
			@cab_files = []
			#
			## 1.1 number of files
			@cab_header['numfiles'] = num_files
			## 2.1 number of blocks
			@cab_folder['numblocks'] = num_blocks
			@cab_folder['offset'] = Lcab::FILEOFFSET + data_offset
			#
			## 1.3 header size part 2
			@cab_header['size'] = header_size
			#
			@cab_files = cab_files
		end

		def strip_path=(flag)
			@strip_path = !!flag
		end

		def write_cab(cab_file)
			logger.info "#{num_files} files, #{total_file_size} bytes, #{num_blocks} blocks"
			File.open(cab_file, 'wb') do |file|
				write_header file
				write_folder file
				write_files file
				write_data file
			end
		end

		def get_cab_string
			logger.info "#{num_files} files, #{total_file_size} bytes, #{num_blocks} blocks"
			cab = ''
			write_header cab
			write_folder cab
			write_files cab
			write_data cab
			return cab
		end

		private

		## write the header
		def write_header(file)
			logger.info "writing header"
			write_byte_buffer( file, @cab_header['sig'] )
			write_dword( file, @cab_header['res1'] )
			write_dword( file, @cab_header['size'] )
			write_dword( file, @cab_header['res2'] )
			write_dword( file, @cab_header['offset'] )
			write_dword( file, @cab_header['res3'] )
			write_byte( file, @cab_header['vmin'] )
			write_byte( file, @cab_header['vmaj'] )
			write_word( file, @cab_header['numfolders'] )
			write_word( file, @cab_header['numfiles'] )
			write_word( file, @cab_header['flags'] )
			write_word( file, @cab_header['setid'] )
			write_word( file, @cab_header['cabid'] )
		end

		## write the folder
		def write_folder(file)
			logger.info "writing folder"
			write_dword( file, @cab_folder['offset'] )
			write_word( file, @cab_folder['numblocks'] )
			write_word( file, @cab_folder['typecmp'] )
		end

		## write the files
		def write_files(file)
			logger.info "writing files"
			@cab_files.each do |cab_file|
				write_dword( file, cab_file['size'] )
				write_dword( file, cab_file['offset'] )
				write_word( file, cab_file['index'] )
				write_word( file, cab_file['date'] )
				write_word( file, cab_file['time'] )
				write_word( file, cab_file['fileattr'] )
				write_byte_buffer( file, cab_file['name'] )
			end
		end

		## write the actual data
		def write_data(file)
			logger.info "writing data"
			# filelist cabblocks
			block = 0				## which block to use
			block_remaining = Lcab::BLOCKSIZE	## keep track of bytes, in a block, that remain to be written,

			@file_list.each do |file_spec|
				#my $rhcabblock = $$racabblocks[ $block ];
				cab_block = @cab_blocks[block]
				buffer = nil				## read data
				bytes_read = 0				## bytes read per loop
				                            ## open input file
				unless file_spec['data']
					File.open(file_spec['path'], 'rb') do |input_file|
						file_spec['data'] = input_file.read(input_file.stat.size)
					end
				end

				## try to read full blocks
				idx = 0
				while ( buffer = file_spec['data'][idx, block_remaining] and idx < file_spec['data'].size  ) do
					bytes_read = buffer.size
					idx += bytes_read
					if !(cab_block['header'] && cab_block['header'] != 0)
						write_dword( file, cab_block['checksum'] )
						write_word( file, cab_block['numcbytes'] )
						write_word( file, cab_block['numubytes'] )
						cab_block['header'] = 1
					end
					write_byte_buffer( file, buffer )
					## could read full block
					if bytes_read == Lcab::BLOCKSIZE
						## next block
						cab_block = @cab_blocks[block += 1]
						block_remaining = Lcab::BLOCKSIZE
						## could not read full block (either to complete a block or when eof)
					else
						block_remaining -= bytes_read
						## next block if block is complete
						if block_remaining == 0
							cab_block = @cab_blocks[block += 1]
							block_remaining = Lcab::BLOCKSIZE
						end
					end
				end
			end
		end

		## make (unsigned long int) CHECKSUM;
		#def write_checksum(file, checksum)
		#write_dword(file, checksum)
		#end

		## write (unsigned char) single byte with pack;
		def write_byte(file, byte)
			#syswrite( FP, pack("C",$scalar) );
			file << [ byte ].pack('C')
		end

		## write sequential (unsigned char) byte;
		def write_byte_buffer(file, buffer)
			#syswrite( FP, $scalar );
			logger.debug "write_byte_buffer() length = #{buffer.size}" if TRACE
			buffer.each_byte { |byte| write_byte(file, byte) }
		end

		## write (unsigned short int) word;
		def write_word(file, word)
			if word =~ /[\0\/a-zA-Z]/
				logger.debug "write_word() [matched] word = #{word.inspect}" if TRACE
				#my $fmt = "S".length($scalar);
				#syswrite( FP, pack( "$fmt", @f ) );
				# TODO: copied but does not seem to happen at all ...
				file << word.unpack('a' * word.size).pack('S' * word.size)
			else
				logger.debug "write_word() word = #{word.inspect}" if TRACE
				#syswrite( FP, pack("S", $scalar) );
				# word here is expected to-be a number (string will fail)
				file << [ word ].pack('S')
			end
		end

		## write (unsigned long int) dword;
		def write_dword(file, dword)
			if dword =~ /[\0\/a-zA-Z]/
				logger.debug "write_dword() [matched] dword = #{dword.inspect}" if TRACE
				#my $fmt = "L".length($scalar);
				#syswrite( FP, pack( "$fmt", @f ) );
				# TODO: copied but does not seem to happen at all ...
				file << dword.unpack('a' * dword.size).pack('L' * dword.size)
			else
				logger.debug "write_dword() dword = #{dword.inspect}" if TRACE
				#syswrite( FP, pack("L",$scalar) );
				# dword here is expected to-be a number (string will fail)
				file << [ dword ].pack('L')
			end
		end

		private

		def file_list
			@file_list
		end

		def total_file_size
			get_total_file_size(@file_list)
		end

		def num_files
			#@file_list.size + 1
			@file_list.size
		end

		def num_blocks
			total_file_size / Lcab::BLOCKSIZE + 1
		end

		def strip_path?
			@strip_path || false # by default don't strip !
		end

		def header_size_1
			header_size = Lcab::FILEOFFSET + num_files * 16
			@file_list.each do |file_spec|
				path = file_spec['path']
				path = strip_path? ? strip_path(path) : make_win_path(path)
				header_size += (path.size + 1)
			end
			header_size += (num_blocks * 8)
			return header_size
		end

		def data_offset
			data_offset = 0
			@file_list.each do |file_spec|
				path = file_spec['path']
				path = strip_path? ? strip_path(path) : make_win_path(path)
				data_offset += (16 + path.size + 1)
			end
			return data_offset
		end

		def header_size
			header_size = header_size_1()
			total_file_size = total_file_size()
			if total_file_size < Lcab::BLOCKSIZE ## just one block
				new_cab_block = { 'header' => 0,				## to be used while writing, 0: write the header, 1: don't
				                  'checksum' => 0,                              ## datablock's checksum
				                  'numcbytes' => total_file_size,		## number of compressed bytes (not supported, = numubytes )
				                  'numubytes' => total_file_size	}	## number of uncompressed bytes
				@cab_blocks << new_cab_block
				header_size += total_file_size	## 1.2 header size part 1
			else
				num_blocks = num_blocks()
				num_blocks.times do |iblock|
					if iblock != (num_blocks - 1)
						new_cab_block = {	'header' => 0,
						                     'checksum' => 0,
						                     'numcbytes' => Lcab::BLOCKSIZE,
						                     'numubytes' => Lcab::BLOCKSIZE	}
						@cab_blocks << new_cab_block
						header_size += Lcab::BLOCKSIZE	## 1.2 header size part 1
					else
						total_file_size -= Lcab::BLOCKSIZE * (num_blocks - 1)
						new_cab_block = {	'header' => 0,
						                     'checksum' => 0,
						                     'numcbytes' => total_file_size,
						                     'numubytes' => total_file_size	}
						@cab_blocks << new_cab_block
						header_size += total_file_size	## 1.2 header size part 1
					end
				end
			end
			return header_size
		end

		def cab_files
			cab_files = []
			@file_list.each do |file_spec|
				new_cab_file = {	'size' => 0,		## filesize
				                    'offset' => 0,		## offset of file in folder
				                    'index' => 0,		## 0 (not supported)
				                    'date' => 0,		## file date
				                    'time' => 0,		## file time
				                    'fileattr' => 0,	## file attributes
				                    'name' => ""		}
				new_cab_file['size'] = file_spec['size']
				path = file_spec['path']
				path = strip_path? ? strip_path(path) : make_win_path(path)
				new_cab_file['name'] = "#{path}\0"
				if cab_files.size == 0
					new_cab_file['offset'] = 0
				else
					i = cab_files.size - 1
					prev_new_cab_file = cab_files[i]; prev_file_spec = @file_list[i]
					new_cab_file['offset'] = prev_new_cab_file['offset'] + prev_file_spec['size']
				end
				## 4.1.4 set file's date and time
				new_cab_file['date'] = make_cab_file_date(file_spec)
				new_cab_file['time'] = make_cab_file_time(file_spec)
				## 4.1.5 set file attributes
				new_cab_file['fileattr'] = 32 # 0x20
				cab_files << new_cab_file
			end
			return cab_files
		end

	end

end

## options
#my %opts;
#my $opts_string = "hvso:";
#getopts( "$opts_string", \%opts ) || usage();
## check the options
#if( !%opts || !defined($opts{o}) || defined($opts{h}) || $#ARGV == -1 ) { usage(); }

# run as a script :
if __FILE__ == $0
	require 'optparse'
	require 'ostruct'

	# Set defaults
	options = OpenStruct.new
	options.verbose = false
	options.debug = false
	options.strip = false
	options.output = nil

	# Specify options
	opts = OptionParser.new do |opts|
		opts.banner = "Usage: lcab.rb [options] [input...]"
		opts.separator ""
		opts.separator "Available options:"

		opts.on('-o', '--output [cabfile]', 'Output cabinet file') { |out| options.output = out }
		# TODO does not work correctly with -s
		opts.on('-s', '--strip', 'Strip the paths') { options.strip = true }

		opts.on('-v', '--verbose') { options.verbose = true }
		opts.on('-d', '--debug') { options.debug = true }

		opts.on_tail('-h', '--help', 'Show this message') { puts opts; exit }

	end

	opts.parse! ARGV

	(puts opts; exit) if opts.default_argv.empty?

	options.input = opts.default_argv

	cab_file = Lcab::CabFile.new
	cab_file.logger.level = Logger::INFO if options.verbose
	cab_file.logger.level = Logger::DEBUG if options.debug
	cab_file.file_list = options.input
	cab_file.strip_path = options.strip
	cab_file.write_cab(options.output)

end