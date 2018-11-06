FactoryBot.define do
  factory :mdm_cred, :aliases => [:cred], :class => Mdm::Cred do
    #
    # Associations
    #
    association :service, :factory => :mdm_service

    active true
    pass{ generate :mdm_cred_pass }
    ptype 'password'
    user{ generate :mdm_user_username }
  end

  sequence :mdm_cred_pass do |n|
    "mahp455w3rd!-#{n}"
  end
end
