module MetasploitDataModels::ActiveRecordModels::Macro
  def self.included(base)
    base.class_eval{

      extend MetasploitDataModels::SerializedPrefs

      serialize :actions, ::MetasploitDataModels::Base64Serializer.new
      serialize :prefs, ::MetasploitDataModels::Base64Serializer.new
      serialized_prefs_attr_accessor :max_time

      validates :name, :presence => true, :format => /^[^'|"]+$/
    }
  end
end

