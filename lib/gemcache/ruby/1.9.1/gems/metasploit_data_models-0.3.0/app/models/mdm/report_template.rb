class Mdm::ReportTemplate < ActiveRecord::Base
  #
  # Callbacks
  #

  before_destroy :delete_file

  #
  # Relations
  #

  belongs_to :workspace, :class_name => 'Mdm::Workspace'

  private

  def delete_file
    c = Pro::Client.get rescue nil
    if c
      c.report_template_delete_file(self[:id])
    else
      ::File.unlink(self.path) rescue nil
    end
  end

  ActiveSupport.run_load_hooks(:mdm_report_template, self)
end

