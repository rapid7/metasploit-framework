module MetasploitDataModels::ActiveRecordModels::Session
  def self.included(base)
    base.class_eval {
      belongs_to :host, :class_name => "Mdm::Host"

      has_one :workspace, :through => :host, :class_name => "Mdm::Workspace"

      has_many :events, :class_name => "Mdm::SessionEvent", :order => "created_at", :dependent => :delete_all
      has_many :routes, :class_name => "Mdm::Route", :dependent => :delete_all

      scope :alive, where("closed_at IS NULL")
      scope :dead, where("closed_at IS NOT NULL")

      serialize :datastore, ::MetasploitDataModels::Base64Serializer.new

      before_destroy :stop

      private

      def stop
        c = Pro::Client.get
        c.session_stop(self.local_id) rescue nil # ignore exceptions (XXX - ideally, stopped an already-stopped session wouldn't throw XMLRPCException)
      end
    }
  end
end
