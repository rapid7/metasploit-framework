FactoryBot.modify do
  factory :mdm_module_detail do
    transient do
      root {
        Metasploit::Framework.root
      }
    end
  end
end
