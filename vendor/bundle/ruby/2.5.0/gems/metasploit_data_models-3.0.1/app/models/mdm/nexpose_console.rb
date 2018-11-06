# A connection to Nexpose from Metasploit.
class Mdm::NexposeConsole < ActiveRecord::Base
  
  #
  # Associations
  #

  # Details for vulnerabilities supplied by this Nexpose console.
  has_many :vuln_details,
           class_name: 'Mdm::VulnDetail',
           foreign_key: :nx_console_id,
           inverse_of: :nexpose_console

  #
  # Attributes
  #

  # @!attribute address
  #   Address on which Nexpose is running.
  #
  #   @return [String]

  # @!attribute cert
  #   @return [String]

  # @!attribute created_at
  #   When this Nexpose console was created.
  #
  #   @return [DateTime]

  # @!attribute enabled
  #   Whether metasploit tried to connect to this Nexpose console.
  #
  #   @return [false] is not allowed to connect.
  #   @return [true] is allowed to connect.

  # @!attribute name
  #   Name of this Nexpose console to differentiate from other Nexpose consoles.
  #
  #   @return [String]

  # @!attribute owner
  #   {Mdm::User#username Name of user} that setup this console.
  #
  #   @return [String]
  #   @todo https://www.pivotaltracker.com/story/show/52413415

  # @!attribute password
  #   Password used to authenticate to Nexpose.
  #
  #   @return [String]
  #   @todo https://www.pivotaltracker.com/story/show/52414551

  # @!attribute port
  #   Port on {#address} that Nexpose is running.
  #
  #   @return [Integer]

  # @!attribute status
  #   Status of the connection to Nexpose.
  #
  #   @return [String]

  # @!attribute updated_at
  #   The last time this Nexpose console was updated.
  #
  #   @return [DateTime]

  # @!attribute username
  #   Username used to authenticate to Nexpose.
  #
  #   @return [String]

  # @!attribute version
  #   The version of Nexpose.  Used to handle protocol difference in different versions of Nexpose.
  #
  #   @return [String]

  #
  # Callbacks
  #

  before_save :strip_protocol

  #
  # Serializations
  #

  # @!attribute [rw] cached_sites
  #   List of sites known to Nexpose.
  #
  #   @return [Array<String>] Array of site names.
  serialize :cached_sites, MetasploitDataModels::Base64Serializer.new

  #
  # Validations
  #

  validates :address, :presence => true
  validates :name, :presence => true
  validates :password, :presence => true
  validates :port, :numericality => { :only_integer => true }, :inclusion => {:in => 1..65535}
  validates :username, :presence => true

  #
  # Instance Methdos
  #

  # Strips '`http://`' or `'https://'` from {#address}.
  #
  # @return [void]
  def strip_protocol
    self.address.gsub!(/^http(s)*:\/\//i,'')
  end

  Metasploit::Concern.run(self)
end

