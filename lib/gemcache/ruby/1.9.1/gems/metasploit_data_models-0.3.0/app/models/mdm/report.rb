class Mdm::Report < ActiveRecord::Base
  #
  # Callbacks
  #

  before_destroy :delete_file

  #
  # Relations
  #

  belongs_to :workspace, :class_name => 'Mdm::Workspace'

  #
  # Scopes
  #

  scope :flagged, where('reports.downloaded_at is NULL')

  #
  # Serializations
  #

  serialize :options, MetasploitDataModels::Base64Serializer.new

  #
  # Validations
  #

  validates :name,
            :format => {
                :allow_blank => true,
                :message => "name must consist of A-Z, 0-9, space, dot, underscore, or dash",
                :with => /^[A-Za-z0-9\x20\x2e\x2d\x5f\x5c]+$/
            }

  private

  def delete_file
    c = Pro::Client.get rescue nil
    if c
      c.report_delete_file(self[:id])
    else
      ::File.unlink(self.path) rescue nil
    end
  end

  ActiveSupport.run_load_hooks(:mdm_report, self)
end

