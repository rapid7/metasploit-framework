FactoryGirl.define do
  trait :metasploit_model_base do
    to_create do |instance|
      # validate so before validation derivation occurs to mimic create for ActiveRecord.
      unless instance.valid?
        raise Metasploit::Model::Invalid.new(instance)
      end
    end
  end
end