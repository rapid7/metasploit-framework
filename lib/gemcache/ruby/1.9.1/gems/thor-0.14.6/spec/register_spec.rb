require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

class BoringVendorProvidedCLI < Thor
  desc "boring", "do boring stuff"
  def boring
    puts "bored. <yawn>"
  end
end

class ExcitingPluginCLI < Thor
  desc "hooray", "say hooray!"
  def hooray
    puts "hooray!"
  end

  desc "fireworks", "exciting fireworks!"
  def fireworks
    puts "kaboom!"
  end
end

class SuperSecretPlugin < Thor
  default_task :squirrel

  desc "squirrel", "All of secret squirrel's secrets"
  def squirrel
    puts "I love nuts"
  end
end

class GroupPlugin < Thor::Group
  desc "part one"
  def part_one
    puts "part one"
  end

  desc "part two"
  def part_two
    puts "part two"
  end
end


BoringVendorProvidedCLI.register(
  ExcitingPluginCLI,
  "exciting",
  "do exciting things",
  "Various non-boring actions")

BoringVendorProvidedCLI.register(
  SuperSecretPlugin,
  "secret",
  "secret stuff",
  "Nothing to see here. Move along.",
  :hide => true)

BoringVendorProvidedCLI.register(
  GroupPlugin,
  'groupwork',
  "Do a bunch of things in a row",
  "purple monkey dishwasher")

describe ".register-ing a Thor subclass" do
  it "registers the plugin as a subcommand" do
    fireworks_output = capture(:stdout) { BoringVendorProvidedCLI.start(%w[exciting fireworks]) }
    fireworks_output.should == "kaboom!\n"
  end

  it "includes the plugin's usage in the help" do
    help_output = capture(:stdout) { BoringVendorProvidedCLI.start(%w[help]) }
    help_output.should include('do exciting things')
  end

  context "when hidden" do
    it "omits the hidden plugin's usage from the help" do
      help_output = capture(:stdout) { BoringVendorProvidedCLI.start(%w[help]) }
      help_output.should_not include('secret stuff')
    end

    it "registers the plugin as a subcommand" do
      secret_output = capture(:stdout) { BoringVendorProvidedCLI.start(%w[secret squirrel]) }
      secret_output.should == "I love nuts\n"
    end
  end
end

describe ".register-ing a Thor::Group subclass" do
  it "registers the group as a single command" do
    group_output = capture(:stdout) { BoringVendorProvidedCLI.start(%w[groupwork]) }
    group_output.should == "part one\npart two\n"
  end
end
