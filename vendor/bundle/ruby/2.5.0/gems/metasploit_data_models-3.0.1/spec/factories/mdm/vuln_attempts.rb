FactoryBot.define do
  factory :mdm_vuln_attempt, :class => Mdm::VulnAttempt do
    #
    # Associations
    #
    association :vuln, :factory => :mdm_vuln
  end
end
