FactoryBot.define do
  factory :exported_web_vuln, :parent => :mdm_web_vuln do
    blame { generate :mdm_web_vuln_blame }
    description { generate :mdm_web_vuln_description }
  end

  sequence :mdm_web_vuln_blame do |n|
    "Blame employee ##{n}"
  end

  sequence :mdm_web_vuln_description do |n|
    "Mdm::WebVuln#description #{n}"
  end
end
