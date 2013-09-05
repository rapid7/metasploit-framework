shared_examples_for 'Msf::DBManager#update_module_details with module' do |options={}|
	options.assert_valid_keys(:reference_name, :type)

	reference_name = options.fetch(:reference_name)
	type = options.fetch(:type)

	context "with #{type.inspect}" do
		let(:module_reference_name) do
			reference_name
		end

		let(:module_type) do
			type
		end

		it "should use module_instance with #{type.inspect} type" do
			module_instance.type.should == type
		end

		it 'should not raise error' do
			expect {
				update_module_details
			}.to_not raise_error
		end
	end
end