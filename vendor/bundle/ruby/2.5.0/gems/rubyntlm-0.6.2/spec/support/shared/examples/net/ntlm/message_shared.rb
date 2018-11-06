shared_examples_for 'a message' do |flags|

  subject(:test_message) do
    unless described_class.names.include?(:flag)
      described_class.int32LE(:flag, {:value => Net::NTLM::DEFAULT_FLAGS[:TYPE1] })
    end
    described_class.new
  end

  it { should respond_to :has_flag? }
  it { should respond_to :set_flag }
  it { should respond_to :dump_flags }
  it { should respond_to :encode64 }
  it { should respond_to :decode64 }
  it { should respond_to :head_size }
  it { should respond_to :data_size }
  it { should respond_to :size }
  it { should respond_to :security_buffers }
  it { should respond_to :deflag }
  it { should respond_to :data_edge }

  flags.each do |flag|
    it "should be able to check if the #{flag} flag is set" do
      expect(test_message.has_flag?(flag)).to be(true)
    end
  end


  it 'should be able to set a new flag' do
    test_message.set_flag(:DOMAIN_SUPPLIED)
    expect(test_message.has_flag?(:DOMAIN_SUPPLIED)).to be(true)
  end


end
