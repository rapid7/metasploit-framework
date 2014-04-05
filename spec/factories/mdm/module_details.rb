FactoryGirl.modify do
  factory :mdm_module_detail do
    ignore do
      root {
        Metasploit::Framework.root
      }
    end
  end
end