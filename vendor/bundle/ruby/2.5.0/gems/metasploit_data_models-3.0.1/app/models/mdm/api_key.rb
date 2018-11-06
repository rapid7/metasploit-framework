# API key to access the RPC.
class Mdm::ApiKey < ActiveRecord::Base
  
  #
  # Attributes
  #

  # @!attribute [rw] created_at
  #   When this API Key was created.
  #
  #   @return [DateTime]

  # @!attribute [rw] token
  #   The API Key to authenicate to the RPC.
  #
  #   @return [String]

  # @!attribute [rw] updated_at
  #   The last time this API Key was updated.
  #
  #   @return [DateTime]

  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  validate :supports_api

  #
  # Attribute Validations
  #

  validates :token, :presence => true, :length => { :minimum => 8 }

  #
  # Instance Methods
  #

  protected


  # Validates whether License supports API.
  #
  # @return [void]
  # @todo MSP-2724
  def supports_api
    license = License.get

    if license and not license.supports_api?
      errors[:license] = " - this product does not support API access"
    end
  end

  Metasploit::Concern.run(self)
end
