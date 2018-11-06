# frozen_string_literal: true

RSpec.describe YARD::I18n::Message do
  def message(id)
    YARD::I18n::Message.new(id)
  end

  before do
    @message = message("Hello World!")
  end

  describe "#id" do
    it "returns ID" do
      expect(message("Hello World!").id).to eq "Hello World!"
    end
  end

  describe "#add_location" do
    it "adds some locations" do
      @message.add_location("hello.rb", 10)
      @message.add_location("message.rb", 5)
      expect(@message.locations).to eq Set.new([["hello.rb", 10], ["message.rb", 5]])
    end
  end

  describe "#add_comment" do
    it "adds some comments" do
      @message.add_comment("YARD.title")
      @message.add_comment("Hello#message")
      expect(@message.comments).to eq Set.new(["YARD.title", "Hello#message"])
    end
  end

  describe "#==" do
    it "returns true for same value messages" do
      locations = [["hello.rb", 10], ["message.rb", 5]]
      comments = ["YARD.title", "Hello#message"]

      other_message = message(@message.id)
      locations.each do |path, line|
        @message.add_location(path, line)
        other_message.add_location(path, line)
      end
      comments.each do |comment|
        @message.add_comment(comment)
        other_message.add_comment(comment)
      end

      expect(@message).to eq other_message
    end
  end
end
