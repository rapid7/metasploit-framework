FactoryBot.define do
  factory :mdm_session_fingerprint, :parent => :mdm_note do
    ntype { 'host.os.session_fingerprint' }
    data { { :os   => "Microsoft Windows XP SP3", :arch => 'x86' } }
  end
end
