# A blank password
class Metasploit::Credential::BlankPassword < Metasploit::Credential::Password
  #
  # Callbacks
  #

  before_save :blank_data

  #
  # Validations
  #

  validates :data,
            uniqueness: true

  #
  # Instance Methods
  #

  # Always makes sure the {Metasploit::Credential::Password#data} is set to an empty string.
  #
  # @return [void]
  def blank_data
    self.data = ''
  end

  Metasploit::Concern.run(self)
end