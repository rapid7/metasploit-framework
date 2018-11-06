# frozen_string_literal: true

RSpec.describe YARD::I18n::Messages do
  def message(id)
    YARD::I18n::Message.new(id)
  end

  def messages
    YARD::I18n::Messages.new
  end

  before do
    @messages = messages
  end

  describe "#each" do
    it "enumerates messages" do
      @messages.register("Hello World!")
      @messages.register("Title")
      enumerated_messages = []
      @messages.each do |message|
        enumerated_messages << message
      end
      enumerated_messages = enumerated_messages.sort_by(&:id)
      expect(enumerated_messages).to eq [message("Hello World!"), message("Title")]
    end

    it "does not yield any message if there are none" do
      enumerated_messages = []
      @messages.each do |message|
        enumerated_messages << message
      end
      expect(enumerated_messages).to eq []
    end
  end

  describe "#[]" do
    it "returns registered message" do
      @messages.register("Hello World!")
      expect(@messages["Hello World!"]).to eq message("Hello World!")
    end

    it "returns nil for nonexistent message ID" do
      expect(@messages["Hello World!"]).to eq nil
    end
  end

  describe "#register" do
    it "returns registered message" do
      expect(@messages.register("Hello World!")).to eq message("Hello World!")
    end

    it "returns existent message" do
      message = @messages.register("Hello World!")
      expect(@messages.register("Hello World!").object_id).to eq message.object_id
    end
  end

  describe "#==" do
    it "returns true for same value messages" do
      @messages.register("Hello World!")
      other_messages = messages
      other_messages.register("Hello World!")
      expect(@messages).to eq other_messages
    end
  end
end
