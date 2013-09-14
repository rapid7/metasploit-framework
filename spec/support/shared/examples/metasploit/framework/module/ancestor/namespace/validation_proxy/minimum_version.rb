shared_examples_for 'Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy#minimum_*_version' do |name|
  attribute_name = "minimum_#{name.underscore}_version"
  constant_name = "Msf::Framework::Version#{name}"
  constant = constant_name.constantize

  context attribute_name do
    it { should allow_value(nil).for(attribute_name) }

    it "should allow value less than #{constant_name}" do
      value = constant / 10.0
      validation_proxy.should allow_value(value).for(attribute_name)
    end

    it "should allow value equal to #{constant_name}" do
      validation_proxy.should allow_value(constant).for(attribute_name)
    end

    it "should not allow value greater than #{constant_name}" do
      value = constant + 1
      validation_proxy.should_not allow_value(value).for(attribute_name)
    end
  end
end