FactoryBot.define do
  factory :mdm_nexpose_console, :aliases => [:nexpose_console], :class => Mdm::NexposeConsole do
    name { generate :mdm_nexpose_console_name }
    port { generate :mdm_tcp_port }
    address { generate :mdm_ipv4_address }
    username {'ConsoleUser'}
    password 's0meH4rdP4ssW0rd'
  end

  sequence :mdm_nexpose_console_name do |n|
    "Nexpose Console Name #{n}"
  end


end
