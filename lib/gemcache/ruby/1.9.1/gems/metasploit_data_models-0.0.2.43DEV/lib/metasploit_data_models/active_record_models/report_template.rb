module MetasploitDataModels::ActiveRecordModels::ReportTemplate
  def self.included(base)
    base.class_eval{

      belongs_to :workspace, :class_name => "Mdm::Workspace"

      before_destroy :delete_file

      private

      def delete_file
				c = Pro::Client.get rescue nil
				if c
					c.report_template_delete_file(self[:id]) 
				else
					::File.unlink(self.path) rescue nil
				end
      end
    }
  end
end

