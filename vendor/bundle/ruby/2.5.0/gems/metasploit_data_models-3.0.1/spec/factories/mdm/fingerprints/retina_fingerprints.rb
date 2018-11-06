FactoryBot.define do
  factory :mdm_retina_fingerprint, :parent => :mdm_note do
    ntype { 'host.os.retina_fingerprint' }
    data { { :os=>"Windows Server 2003 (X64), Service Pack 2"} }
  end
end
