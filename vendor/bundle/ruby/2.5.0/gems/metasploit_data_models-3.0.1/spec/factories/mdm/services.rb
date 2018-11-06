FactoryBot.define do
  factory :mdm_service, :class => Mdm::Service do
    #
    # Associations
    #
    association :host, :factory => :mdm_host

    #
    # Attributes
    #
    name { generate :mdm_service_name }
    port { generate :port }
    proto { generate :mdm_service_proto }
    state 'open'

    factory :web_service do
      proto 'tcp'
      name { FactoryBot.generate(:web_service_name) }
    end
  end

  sequence(:mdm_service_name) { |n|
    "mdm_service_name#{n}"
  }

  sequence :mdm_service_proto, Mdm::Service::PROTOS.cycle

  port_bits = 16
  port_limit = 1 << port_bits

  sequence :port do |n|
    n % port_limit
  end

  web_service_names = ['http', 'https']
  web_service_name_count = web_service_names.length

  sequence :web_service_name do |n|
    web_service_names[n % web_service_name_count]
  end
end
