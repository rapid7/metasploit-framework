
# Implements importation of a zip file containing credentials.  Each well-formed zip should contain one CSV file and a
# subdirectory holding a collection of files, each containing one SSH private key.
class Metasploit::Credential::Importer::Zip
  include Metasploit::Credential::Importer::Base

  #
  # Constants
  #

  # The name of the directory in the zip file's root directory that contains SSH keys
  KEYS_SUBDIRECTORY_NAME = "keys"

  # The name of the file in the zip which is opened and passed as a `File` to an instance of
  # {Metasploit::Credential::Importer::CSV::Core}
  MANIFEST_FILE_NAME = "manifest.csv"

  # Zip file identifying header length in bytes ({ZIP_HEADER_IDENTIFIER} length)
  ZIP_HEADER_BYTE_LENGTH = 4

  # Standard 4-byte binary header for all zips - http://www.fileformat.info/format/zip/corion.htm
  ZIP_HEADER_IDENTIFIER = "PK\x03\x04"

  #
  # Attributes
  #

  # @!attribute manifest_importer
  #   The importer for the zip's manifest file
  #
  #   @return [Metasploit::Credential::Importer::CSV::Manifest]
  attr_accessor :manifest_importer

  # @!attribute extracted_zip_directory
  #   The path to the directory holding the extracted zip contents
  #
  #   @return [String]
  attr_accessor :extracted_zip_directory


  #
  # Validations
  #

  validate :input_is_well_formed

  #
  # Instance Methods
  #

  # Extract the zip file and pass the CSV file contained therein to a
  # {Metasploit::Credential::Importer::CSV::Core}, which is in charge of creating new {Metasploit::Credential::Core}
  # objects, creating new {Metasploit::Credential::Public} objects or linking existing ones, and associating them with
  # extracted {Metasploit::Credential::SSHKey} objects read from the files indicated in the manifest.
  #
  # @return [void]
  def import!
    ::Zip::File.open(input.path) do |zip_file|
      zip_file.each do |entry|
        entry.extract(File.join(extracted_zip_directory, entry.name))
      end
    end

    csv_path = Dir.glob(File.join(extracted_zip_directory,'**', MANIFEST_FILE_NAME)).first
    csv_input = File.open(csv_path)
    Metasploit::Credential::Importer::Core.new(input: csv_input, origin: origin, workspace: workspace).import!
  end

  # Returns the path to the directory where the zip was extracted.
  #
  # @return [String]
  def extracted_zip_directory
    @extracted_zip_directory ||= Dir.mktmpdir
  end


  # Validates that the zip file contains a CSV file and that it
  # can be handled with the {::Zip::File::open} method.
  #
  # @return [void]
  def input_is_well_formed
    begin
      Zip::File.open input.path do |archive|
        glob_check  = archive.glob("**#{File::SEPARATOR}#{MANIFEST_FILE_NAME}")
        if glob_check.present?
          true
        else
          errors.add(:input, :missing_manifest)
        end
      end
    rescue ::Zip::Error
      errors.add(:input, :malformed_archive)
    end
  end

end