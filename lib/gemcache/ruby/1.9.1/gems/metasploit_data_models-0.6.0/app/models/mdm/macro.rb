class Mdm::Macro < ActiveRecord::Base
  extend MetasploitDataModels::SerializedPrefs

  #
  # Serialization
  #

  serialize :actions, MetasploitDataModels::Base64Serializer.new
  serialize :prefs, MetasploitDataModels::Base64Serializer.new
  serialized_prefs_attr_accessor :max_time

  #
  # Validations
  #

  validates :name, :presence => true, :format => /^[^'|"]+$/

  ActiveSupport.run_load_hooks(:mdm_macro, self)
end

