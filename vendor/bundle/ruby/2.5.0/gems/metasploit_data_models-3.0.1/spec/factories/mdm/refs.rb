FactoryBot.define do
  factory :mdm_ref, :class => Mdm::Ref do
    name { generate :mdm_ref_name }
  end

  sequence :mdm_ref_name do |n|
    "Mdm::Ref#name #{n}"
  end
end
