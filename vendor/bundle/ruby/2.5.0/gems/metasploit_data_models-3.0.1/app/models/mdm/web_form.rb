# A filled-in form on a {#web_site}.
class Mdm::WebForm < ActiveRecord::Base
  
  #
  # Associations
  #

  # {Mdm::WebSite Web site} on which this form is.
  belongs_to :web_site,
             class_name: 'Mdm::WebSite',
             inverse_of: :web_forms

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this web form was created.
  #
  #   @return [DateTime]

  # @!attribute method
  #   HTTP method (or verb) used to submitted this form, such as GET or POST.
  #
  #   @return [String]

  # @!attribute path
  #   Path portion of URL to which this form was submitted.
  #
  #   @return [String]

  # @!attribute query
  #   URL query that submitted for this form.
  #
  #   @return [String]

  # @!attribute updated_at
  #   The last time this web form was updated.
  #
  #   @return [DateTime]

  #
  # Serializations
  #

  # Parameters submitted in this form.
  #
  # @return [Array<Array(String, String)>>]
  serialize :params, MetasploitDataModels::Base64Serializer.new

  Metasploit::Concern.run(self)
end

