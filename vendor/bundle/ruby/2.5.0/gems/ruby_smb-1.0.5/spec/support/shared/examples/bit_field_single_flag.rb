RSpec.shared_examples 'bit field with one flag set' do |flag, pack, value|
  it "has a value of #{value} when only #{flag} is set" do
    subject.field_names.each do |sub_field|
      if sub_field == flag
        subject.send(sub_field.to_s.concat('=').to_sym, 1)
      else
        subject.send(sub_field.to_s.concat('=').to_sym, 0)
      end
    end
    field_val = subject.to_binary_s
    field_val = field_val.unpack(pack).first
    expect(field_val).to eq value
  end
end
