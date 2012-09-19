module MetasploitDataModels::ActiveRecordModels::Note
  def self.included(base)
    base.class_eval{
      notes = base.arel_table

      belongs_to :workspace, :class_name => "Mdm::Workspace"
      belongs_to :host, :class_name => "Mdm::Host", :counter_cache => :note_count
      belongs_to :service, :class_name => "Mdm::Service"
      serialize :data, ::MetasploitDataModels::Base64Serializer.new

      scope :flagged, where('critical = true AND seen = false')
      scope :visible, where(notes[:ntype].not_in(['web.form', 'web.url', 'web.vuln']))
      scope :search, lambda { |*args|
        where(["(data NOT ILIKE 'BAh7%' AND data LIKE ?)" +
          "OR (data ILIKE 'BAh7%' AND decode(data, 'base64') LIKE ?)" +
          "OR ntype ILIKE ?",
          "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%"
        ])
      }


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

