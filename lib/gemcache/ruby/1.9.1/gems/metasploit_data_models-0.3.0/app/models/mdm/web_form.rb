class Mdm::WebForm < ActiveRecord::Base
  #
  # Relations
  #

  belongs_to :web_site, :class_name => 'Mdm::WebSite'

  #
  # Serializations
  #

  serialize :params, MetasploitDataModels::Base64Serializer.new

  ActiveSupport.run_load_hooks(:mdm_web_form, self)
end

