class Mdm::Profile < ActiveRecord::Base
  #
  # Serializations
  #
  serialize :settings, MetasploitDataModels::Base64Serializer.new

  ActiveSupport.run_load_hooks(:mdm_profile, self)
end

