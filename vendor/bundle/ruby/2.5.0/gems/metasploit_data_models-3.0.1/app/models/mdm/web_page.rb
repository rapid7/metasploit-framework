# Web page requested from a {#web_site}.
class Mdm::WebPage < ActiveRecord::Base
  
  #
  # Associations
  #

  # Mdm::WebSite Web site} from which this page was requested.
  belongs_to :web_site,
             class_name: 'Mdm::WebSite',
             inverse_of: :web_pages

  #
  # Attributes
  #

  # @!attribute auth
  #   Credentials sent to server to authenticate to web site to allow access to this web page.
  #
  #   @return [String]

  # @!attribute body
  #   Body of response from server.
  #
  #   @return [String]

  # @!attribute code
  #   HTTP Status code return from {#web_site} when requesting this web page.
  #
  #   @return [Integer]

  # @!attribute cookie
  #   Cookies derived from {#headers}.
  #
  #   @return [String]

  # @!attribute created_at
  #   When this web page was created.
  #
  #   @return [DateTime]

  # @!attribute ctype
  #   The content type derived from the {#headers} of the returned web page.
  #
  #   @return [String]

  # @!attribute location
  #   Location derived from {#headers}.

  #   @return [String]

  # @!attribute mtime
  #   The last modified time of the web page derived from the {#headers}.
  #
  #   @return [DateTime]

  # @!attribute path
  #   Path portion of URL that was used to access this web page.
  #
  #   @return [String]

  # @!attribute query
  #   Query portion of URLthat was used to access this web page.
  #
  #   @return [String]

  # @!attribute request
  #   Request sent to server to cause this web page to be returned.
  #
  #   @return [String]

  # @!attribute updated_at
  #   The last time this web page was updated.
  #
  #   @return [DateTime]

  #
  # Serializations
  #

  # Headers sent from server.
  #
  # @return [Hash{String => String}]
  serialize :headers, MetasploitDataModels::Base64Serializer.new

  # Cookies sent from server.
  #
  # @return [Hash{String => String}]
  serialize :cookie
  Metasploit::Concern.run(self)
end

