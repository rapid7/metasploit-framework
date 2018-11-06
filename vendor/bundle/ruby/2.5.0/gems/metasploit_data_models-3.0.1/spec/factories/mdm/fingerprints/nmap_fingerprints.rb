FactoryBot.define do
  factory :mdm_nmap_fingerprint, :parent => :mdm_note do
    ntype { 'host.os.nmap_fingerprint' }
    data { { :os_accuracy => 100, :os_family=> 'Windows',  :os_vendor=> 'Microsoft', :os_version => 'XP' } }
  end
end
