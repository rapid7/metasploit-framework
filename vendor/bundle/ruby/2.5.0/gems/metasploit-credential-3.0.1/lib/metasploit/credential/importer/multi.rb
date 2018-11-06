#
# Standard Library
#

require 'csv'
require 'pathname'

# {Metasploit::Credential::Importer::Multi} allows a single class to pass off a file to the correct importer as
# long as the file meets certain basic requirements.  Each file type is identified, and if supported, another class
# in the {Metasploit::Credential::Importer} namespace is instantiated with the `#input` attribute passed in there.
class Metasploit::Credential::Importer::Multi
  include Metasploit::Credential::Importer::Base

  #
  # Attributes
  #

  # @!attribute selected_importer
  #   An instance of the importer class which will handle the processing of input into the system.
  #   @return [IO]
  attr_accessor :selected_importer

  #
  # Validations
  #

  validate :is_supported_format

  #
  # Instance Methods
  #

  def initialize(args={})
    @selected_importer = nil
    super(args)

    if zip?
      @selected_importer = Metasploit::Credential::Importer::Zip.new(input: input, origin: origin, workspace: workspace)
    elsif csv?
      @selected_importer = Metasploit::Credential::Importer::Core.new(input: input, origin: origin, workspace: workspace)
    end
  end

  # Perform the import. Return true if import succeeded. Return false if any cred failed due to formatting.
  #
  # @return [Boolean]
  def import!
    return selected_importer.import!
  end


  # True if the file can be opened with `Zip::File::open`, false otherwise
  #
  # @return [Boolean]
  def zip?
    begin
      ::Zip::File.open input.path
      true
    rescue ::Zip::Error
      false
    end
  end

  # True if the file has a comma in the first place there should be one.
  # Further validation for well-formedness is available in {Metasploit::Credential::Importer::Core}
  #
  # @return [Boolean]
  def csv?
    test_header_byte_length = Metasploit::Credential::Importer::Core::VALID_SHORT_CSV_HEADERS.first.size + 1
    test_bytes              =  input.read(test_header_byte_length)
    if test_bytes.present? && test_bytes.include?(',')
      input.rewind
      true
    else
      false
    end
  end

  private

  # True if the format of `#input` is supported for import
  #
  # @return [Boolean]
  def is_supported_format
    if zip? || csv?
      true
    else
      errors.add(:input, :unsupported_file_format)
    end
  end
end