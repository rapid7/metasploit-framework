shared_context 'Msf::UIDriver' do
	let(:driver) do
		mock(
			'Driver',
			:framework => framework
		).tap { |driver|
			driver.stub(:on_command_proc=).with(kind_of(Proc))
			driver.stub(:print_line).with(kind_of(String)) do |string|
				@output ||= []
				@output.concat string.split("\n")
			end
			driver.stub(:print_error).with(kind_of(String)) do |string|
				@error ||= []
				@error.concat string.split("\n")
			end
		}
	end
end
