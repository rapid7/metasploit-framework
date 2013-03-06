FactoryGirl.define do
  factory :mdm_web_site, :class => Mdm::WebSite do
    #
    # Associations
    #
    association :service, :factory => :mdm_service
  end
end