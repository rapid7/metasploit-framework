class Mdm::Task < ActiveRecord::Base
  #
  # Callbacks
  #

  before_destroy :delete_file

  #
  # Relations
  #

  belongs_to :workspace, :class_name => "Mdm::Workspace"

  #
  # Scopes
  #

  scope :running, order( "created_at DESC" ).where("completed_at IS NULL")

  #
  # Serializations
  #

  serialize :options, MetasploitDataModels::Base64Serializer.new
  serialize :result, MetasploitDataModels::Base64Serializer.new
  serialize :settings, MetasploitDataModels::Base64Serializer.new

  private

  def delete_file
    c = Pro::Client.get rescue nil
    if c
      c.task_delete_log(self[:id]) if c
    else
      ::File.unlink(self.path) rescue nil
    end
  end

  ActiveSupport.run_load_hooks(:mdm_task, self)
end

