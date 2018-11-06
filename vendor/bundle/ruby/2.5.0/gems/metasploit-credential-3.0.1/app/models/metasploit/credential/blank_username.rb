# A public credential in the form of a Username.
class Metasploit::Credential::BlankUsername < Metasploit::Credential::Public
  #
  # Callbacks
  #

  before_save :blank_username

  #
  # Validations
  #

  validates :username,
            uniqueness: true

  #
  # Instance Methods
  #

  # This method always makes sure the BlankUsername is set to an empty string.
  #
  # @return [void]
  def blank_username
    self.username = ''
  end

  Metasploit::Concern.run(self)
end