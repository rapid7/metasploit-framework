class Mdm::VulnAttempt < ActiveRecord::Base
  #
  # Relations
  #

  belongs_to :vuln, :class_name => 'Mdm::Vuln', :counter_cache => :vuln_attempt_count

  #
  # Validations
  #

  validates :vuln_id, :presence => true

  ActiveSupport.run_load_hooks(:mdm_vuln_attempt, self)
end
