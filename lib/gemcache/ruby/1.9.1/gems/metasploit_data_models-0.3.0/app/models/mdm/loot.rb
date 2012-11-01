module MetasploitDataModels::ActiveRecordModels::Loot
  def self.included(base)
    base.class_eval {

      belongs_to :workspace, :class_name => "Mdm::Workspace"
      belongs_to :host, :class_name => "Mdm::Host"
      belongs_to :service, :class_name => "Mdm::Service"

      serialize :data, ::MetasploitDataModels::Base64Serializer.new

      before_destroy :delete_file

      scope :search, lambda { |*args|
        where(["loots.ltype ILIKE ? OR " +
       "loots.name ILIKE ? OR " +
       "loots.info ILIKE ? OR " +
       "loots.data ILIKE ?",
          "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%"
        ])
      }

      private

      def delete_file
				c = Pro::Client.get rescue nil
				if c
					c.loot_delete_file(self[:id])
				else
					::File.unlink(self.path) rescue nil
				end
      end
    }
  end
end

