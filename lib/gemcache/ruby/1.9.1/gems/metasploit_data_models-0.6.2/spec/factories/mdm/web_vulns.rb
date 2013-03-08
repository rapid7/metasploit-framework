FactoryGirl.define do
  factory :mdm_web_vuln, :class => Mdm::WebVuln do
    #
    # Associations
    #
    association :web_site, :factory => :mdm_web_site

    #
    # Attributes
    #

    category { generate :mdm_web_vuln_category }
    confidence { generate :mdm_web_vuln_confidence }
    method { generate :mdm_web_vuln_method }
    name { generate :mdm_web_vuln_name }
    path { generate :mdm_web_vuln_path }
    params { generate :mdm_web_vuln_params }
    pname { params.first.first }
    proof { generate :mdm_web_vuln_proof }
    risk { generate :mdm_web_vuln_risk }
  end

  sequence :mdm_web_vuln_category do |n|
    "mdm_web_vuln_category_#{n}"
  end

  sequence :mdm_web_vuln_confidence do |n|
    # range is from 0 to 100
    n % 101
  end

  method_count = Mdm::WebVuln::METHODS.length

  sequence :mdm_web_vuln_method do |n|
    Mdm::WebVuln::METHODS[n % method_count]
  end

  sequence :mdm_web_vuln_name do |n|
    "Web Vulnerability #{n}"
  end

  sequence :mdm_web_vuln_path do |n|
    "path/to/vulnerability/#{n}"
  end

  sequence :mdm_web_vuln_params do |n|
    [
        [
            "param#{n}",
            "value#{n}"
        ]
    ]
  end

  sequence :mdm_web_vuln_proof do |n|
    "Mdm::WebVuln Proof #{n}"
  end

  sequence :mdm_web_vuln_risk do |n|
    # range is 0 .. 5
    n % 6

  end
end