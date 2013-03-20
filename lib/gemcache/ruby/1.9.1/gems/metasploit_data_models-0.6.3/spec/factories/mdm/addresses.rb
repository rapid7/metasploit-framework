FactoryGirl.define do
  sequence :mdm_ipv4_address do |n|
    max = 255

    "192.168.#{(n / max).to_i}.#{n % max}"
  end
end