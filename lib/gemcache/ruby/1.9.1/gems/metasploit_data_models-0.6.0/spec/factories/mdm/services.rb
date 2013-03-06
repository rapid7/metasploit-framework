FactoryGirl.define do
  factory :mdm_service, :class => Mdm::Service do
    #
    # Associations
    #
    association :host, :factory => :mdm_host

    #
    # Attributes
    #
    port 4567
    proto 'snmp'
    state 'open'

    factory :web_service do
      proto 'tcp'
      name { FactoryGirl.generate(:web_service_name) }
      port { FactoryGirl.generate(:port) }
    end
  end

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