class Mdm::Note < ActiveRecord::Base
  #
  # Callbacks
  #

  after_save :normalize

  #
  # Relations
  #

  belongs_to :workspace, :class_name => "Mdm::Workspace"
  belongs_to :host, :class_name => "Mdm::Host", :counter_cache => :note_count
  belongs_to :service, :class_name => "Mdm::Service"

  #
  # Scopes
  #

  scope :flagged, where('critical = true AND seen = false')

  notes = self.arel_table
  scope :visible, where(notes[:ntype].not_in(['web.form', 'web.url', 'web.vuln']))

  scope :search, lambda { |*args|
    where(["(data NOT ILIKE 'BAh7%' AND data LIKE ?)" +
               "OR (data ILIKE 'BAh7%' AND decode(data, 'base64') LIKE ?)" +
               "OR ntype ILIKE ?",
           "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%"
          ])
  }

  #
  # Serializations
  #

  serialize :data, ::MetasploitDataModels::Base64Serializer.new

  private

  def normalize
    if data_changed? and ntype =~ /fingerprint/
      host.normalize_os
    end
  end

  ActiveSupport.run_load_hooks(:mdm_note, self)
end

