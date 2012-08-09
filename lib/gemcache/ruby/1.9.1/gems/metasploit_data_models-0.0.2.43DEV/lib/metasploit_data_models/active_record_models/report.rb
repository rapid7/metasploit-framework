module MetasploitDataModels::ActiveRecordModels::Report
  def self.included(base)
    base.class_eval {

      belongs_to :workspace, :class_name => "Mdm::Workspace"
      serialize :options, ::MetasploitDataModels::Base64Serializer.new

      validates_format_of :name, :with => /^[A-Za-z0-9\x20\x2e\x2d\x5f\x5c]+$/, :message => "name must consist of A-Z, 0-9, space, dot, underscore, or dash", :allow_blank => true

      serialize :options, MetasploitDataModels::Base64Serializer.new

      before_destroy :delete_file

      scope :flagged, where('reports.downloaded_at is NULL')

      private

      def delete_file
				c = Pro::Client.get rescue nil
				if c
					c.report_delete_file(self[:id]) 
				else
					::File.unlink(self.path) rescue nil
				end
      end
    }
  end
end

