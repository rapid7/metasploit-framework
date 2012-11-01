module MetasploitDataModels::ActiveRecordModels::WebForm
  def self.included(base)
    base.class_eval{
      belongs_to :web_site, :class_name => "Mdm::WebSite"
      serialize :params, ::MetasploitDataModels::Base64Serializer.new
    }
  end
end

