FactoryBot.define do
  factory :mdm_tag, :class => Mdm::Tag do
    desc { generate :mdm_tag_desc }
    name { generate :mdm_tag_name }
  end

  sequence :mdm_tag_desc do |n|
    "Mdm::Tag#description #{n}"
  end

  sequence :mdm_tag_name do |n|
    "mdm_tag_name#{n}"
  end
end
