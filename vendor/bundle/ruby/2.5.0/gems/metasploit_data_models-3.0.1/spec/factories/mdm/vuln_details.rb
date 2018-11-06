FactoryBot.define do
  factory :mdm_vuln_detail, :class => Mdm::VulnDetail do
    #
    # Associations
    #
    association :vuln, :factory => :mdm_vuln
  end
end
