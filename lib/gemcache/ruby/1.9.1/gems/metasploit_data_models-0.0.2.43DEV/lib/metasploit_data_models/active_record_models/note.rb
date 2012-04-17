require 'metasploit_data_models/note_serializer'
module MetasploitDataModels::ActiveRecordModels::Note
  def self.included(base)
    base.class_eval{
      notes = base.arel_table

      belongs_to :workspace, :class_name => "Mdm::Workspace"
      belongs_to :host, :class_name => "Mdm::Host"
      belongs_to :service, :class_name => "Mdm::Service"
      serialize :data, ::MetasploitDataModels::NoteSerializer.new

      scope :flagged, where('critical = true AND seen = false')
      scope :visible, where(notes[:ntype].not_in(['web.form', 'web.url', 'web.vuln']))


      after_save :normalize

      private

      def normalize
        if data_changed? and ntype =~ /fingerprint/
          host.normalize_os
        end
      end
    }
  end
end

