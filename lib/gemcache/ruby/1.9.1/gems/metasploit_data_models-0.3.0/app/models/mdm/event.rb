class Mdm::Event < ActiveRecord::Base
  #
  # Relations
  #

  belongs_to :host, :class_name => 'Mdm::Host'
  belongs_to :workspace, :class_name => 'Mdm::Workspace'

  #
  # Scopes
  #

  scope :flagged, where(:critical => true, :seen => false)
  scope :module_run, where(:name => 'module_run')

  #
  # Serializations
  #

  serialize :info, MetasploitDataModels::Base64Serializer.new

  #
  # Validations
  #

  validates :name, :presence => true

  ActiveSupport.run_load_hooks(:mdm_event, self)
end

