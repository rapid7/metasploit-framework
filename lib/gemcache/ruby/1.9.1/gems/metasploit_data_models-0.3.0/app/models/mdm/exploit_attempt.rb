module MetasploitDataModels::ActiveRecordModels::ExploitAttempt
  def self.included(base)
    base.class_eval {
      belongs_to :host, :class_name => "Mdm::Host", :counter_cache => :exploit_attempt_count
      validates :host_id, :presence => true
    }
  end
end
