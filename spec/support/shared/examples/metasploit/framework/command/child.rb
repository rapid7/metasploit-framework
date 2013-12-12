shared_examples_for 'Metasploit::Framework::Command::Child' do
  context 'validations' do
    it { should validate_presence_of :parent }
  end

  shared_examples_for 'delegates to parent' do |method|
    context "##{method}" do
      # no let name so that it doesn't interfere with outer lets
      subject do
        command.send(method)
      end

      it 'should delegate to #parent' do
        expected = double(method)
        parent.should_receive(method).and_return(expected)

        subject.should == expected
      end
    end
  end

  it_should_behave_like 'delegates to parent', :dispatcher
  it_should_behave_like 'delegates to parent', :option_parser
  it_should_behave_like 'delegates to parent', :partial_word
  it_should_behave_like 'delegates to parent', :words
end