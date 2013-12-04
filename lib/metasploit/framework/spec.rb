module Metasploit::Framework::Spec
  CONFIGURED_NAMES = [
      # profile first so it profiles everything
      'Profile',
      'DatabaseCleaner',
      'FactoryGirl',
      'Constants'
  ]

  # In order that allows later paths to modify early path's factories
  ROOTED_MODULES = [
      Metasploit::Model,
      MetasploitDataModels,
      Metasploit::Framework
  ]

  def self.configure!
    CONFIGURED_NAMES.each do |configured_name|
      configured_module = "#{name}::#{configured_name}".constantize
      configured_module.configure!
    end
  end
end