# -*- coding:binary -*-
shared_examples_for 'Msf::Modules::Error subclass #initialize' do
  context 'instance methods' do
    context '#initialize' do
      include_context 'Msf::Modules::Error attributes'

      subject do
        described_class.new(
            :module_path => module_path,
            :module_reference_name => module_reference_name
        )
      end

      it 'should include causal message in error' do
        subject.to_s.should match(/due to .*/)
      end

      it 'should set module_path' do
        subject.module_path.should == module_path
      end

      it 'should set module_reference_name' do
        subject.module_reference_name.should == module_reference_name
      end
    end
  end
end
