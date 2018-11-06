FactoryBot.define do
  factory :mdm_nessus_fingerprint, :parent => :mdm_note do
    ntype { 'host.os.nessus_fingerprint' }
    data { {:os=>"Microsoft Windows XP SP3"} }
  end
end
