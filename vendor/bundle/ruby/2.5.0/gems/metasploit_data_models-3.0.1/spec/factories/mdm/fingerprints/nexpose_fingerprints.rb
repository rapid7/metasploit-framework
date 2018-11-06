FactoryBot.define do
  factory :mdm_nexpose_fingerprint, :parent => :mdm_note do
    ntype { 'host.os.nexpose_fingerprint' }
    data { {:family=>"Windows", :certainty=>"0.67", :vendor=>"Microsoft", :arch=>"x86"} }
  end
end
