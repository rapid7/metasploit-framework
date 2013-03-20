FactoryGirl.define do
  factory :mdm_user, :class => Mdm::User do
    admin true
    company "Interplanetary Teleportation, LTD"
    email "rwillingham@itl.com"
    fullname { generate :mdm_user_fullname }
    phone "5123334444"
    username { generate :mdm_user_username }
  end

  factory :non_admin_mdm_user, :parent => :mdm_user do
    admin false
  end

  sequence :mdm_user_fullname do |n|
    "Mdm User Fullname the #{n.ordinalize}"
  end

  sequence :mdm_user_username do |n|
    "mdm_user_username#{n}"
  end
end