class Msf::SessionManager::ID
  include Celluloid

  #
  # Attributes
  #

  attr_accessor :current

  def initialize
    self.current = 0
  end

  #
  # Instance Methods
  #

  def next
    self.current += 1
  end
end