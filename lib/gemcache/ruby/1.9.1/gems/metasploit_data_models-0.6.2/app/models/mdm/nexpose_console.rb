class Mdm::NexposeConsole < ActiveRecord::Base
  #
  # Serializations
  #

  serialize :cached_sites, MetasploitDataModels::Base64Serializer.new

  #
  # Validations
  #

  validates :address, :presence => true
  validates :name, :presence => true
  validates :password, :presence => true
  validates :port, :inclusion => {:in => 1..65535}
  validates :username, :presence => true

  ActiveSupport.run_load_hooks(:mdm_nexpose_console, self)
end

