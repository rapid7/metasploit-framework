shared_examples_for 'change tracking for' do |attribute|
	context attribute do
		define_method(:changed?) do
			subject.send("#{attribute}_changed?")
		end

		let(:old_value) do
			subject.send(attribute)
		end

		before(:each) do
			subject.send("#{attribute}=", new_value)
		end

		context 'with same value' do
			let(:new_value) do
				old_value
			end

			it 'should not be changed' do
				changed?.should be_false
			end
		end

		context 'without same value' do
			let(:new_value) do
				"#{old_value}_changed"
			end

			it 'should be changed' do
				changed?.should be_true
			end

			context 'after save!' do
				before(:each) do
					subject.save!
				end

				it 'should not be changed' do
					changed?.should be_false
				end

				it 'should have old change in previous_changes' do
					subject.previous_changes[attribute].should == [old_value, new_value]
				end
			end
		end
	end
end