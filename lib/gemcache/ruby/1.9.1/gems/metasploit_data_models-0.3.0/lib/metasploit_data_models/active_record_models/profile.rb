module MetasploitDataModels::ActiveRecordModels::Profile
  def self.included(base)
    base.class_eval{
      serialize :settings, ::MetasploitDataModels::Base64Serializer.new
    }
  end
end

