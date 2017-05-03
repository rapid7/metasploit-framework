class Mdm::Listener < ActiveRecord::Base
  #
  # Relations
  #

  belongs_to :task, :class_name => 'Mdm::Task'
  belongs_to :workspace, :class_name => 'Mdm::Workspace'

  #
  # Serializations
  #

  serialize :options, MetasploitDataModels::Base64Serializer.new

  #
  # Validations
  #

  validates :address, :ip_format => true, :presence => true
  validates :port, :presence => true

  ActiveSupport.run_load_hooks(:mdm_listener, self)
end

