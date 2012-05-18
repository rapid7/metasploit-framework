module MetasploitDataModels::ActiveRecordModels::Task
  def self.included(base)
    base.class_eval{

      belongs_to :workspace, :class_name => "Mdm::Workspace"

      serialize :options, ::MetasploitDataModels::Base64Serializer.new
      serialize :result, ::MetasploitDataModels::Base64Serializer.new
      serialize :settings, ::MetasploitDataModels::Base64Serializer.new

      scope :running, order( "created_at DESC" ).where("completed_at IS NULL")

      before_destroy :delete_file

      private

      def delete_file
				c = Pro::Client.get rescue nil
				if c
					c.task_delete_log(self[:id]) if c
				else
					::File.unlink(self.path) rescue nil
				end
      end
    }
  end
end

