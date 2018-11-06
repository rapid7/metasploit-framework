require 'spec_helper'

describe Net::NTLM::FieldSet do

  fields = []

  it_behaves_like 'a fieldset', fields

  subject(:fieldset_class) do
    Class.new(Net::NTLM::FieldSet)
  end

  context 'an instance' do
    subject(:fieldset_object) do
      fieldset_class.string(:test_string, { :value => 'Test', :active => true, :size => 4})
      fieldset_class.string(:test_string2, { :value => 'Foo', :active => true, :size => 3})
      fieldset_class.new
    end

    it 'should serialize all the fields' do
      expect(fieldset_object.serialize).to eq('TestFoo')
    end

    it 'should parse a string across the fields' do
      fieldset_object.parse('FooBarBaz')
      expect(fieldset_object.serialize).to eq('FooBarB')
    end

    it 'should return an aggregate size of all the fields' do
      expect(fieldset_object.size).to eq(7)
    end
  end
end
