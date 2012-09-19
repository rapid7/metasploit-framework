# encoding: UTF-8

require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe Thor::Shell::Basic do
  def shell
    @shell ||= Thor::Shell::Basic.new
  end

  describe "#padding" do
    it "cannot be set to below zero" do
      shell.padding = 10
      shell.padding.should == 10

      shell.padding = -1
      shell.padding.should == 0
    end
  end

  describe "#ask" do
    it "prints a message to the user and gets the response" do
      $stdout.should_receive(:print).with("Should I overwrite it? ")
      $stdin.should_receive(:gets).and_return('Sure')
      shell.ask("Should I overwrite it?").should == "Sure"
    end

    it "prints a message to the user with the available options and determines the correctness of the answer" do
      $stdout.should_receive(:print).with('What\'s your favorite Neopolitan flavor? ["strawberry", "chocolate", "vanilla"] ')
      $stdin.should_receive(:gets).and_return('chocolate')
      shell.ask("What's your favorite Neopolitan flavor?", :limited_to => ["strawberry", "chocolate", "vanilla"]).should == "chocolate"
    end

    it "prints a message to the user with the available options and reasks the question after an incorrect repsonse" do
      $stdout.should_receive(:print).with('What\'s your favorite Neopolitan flavor? ["strawberry", "chocolate", "vanilla"] ').twice
      $stdout.should_receive(:puts).with('Your response must be one of: ["strawberry", "chocolate", "vanilla"]. Please try again.')
      $stdin.should_receive(:gets).and_return('moose tracks', 'chocolate')
      shell.ask("What's your favorite Neopolitan flavor?", :limited_to => ["strawberry", "chocolate", "vanilla"]).should == "chocolate"
    end
  end

  describe "#yes?" do
    it "asks the user and returns true if the user replies yes" do
      $stdout.should_receive(:print).with("Should I overwrite it? ")
        $stdin.should_receive(:gets).and_return('y')
      shell.yes?("Should I overwrite it?").should === true

      $stdout.should_receive(:print).with("Should I overwrite it? ")
        $stdin.should_receive(:gets).and_return('n')
      shell.yes?("Should I overwrite it?").should_not === true
    end
  end

  describe "#no?" do
    it "asks the user and returns true if the user replies no" do
      $stdout.should_receive(:print).with("Should I overwrite it? ")
        $stdin.should_receive(:gets).and_return('n')
      shell.no?("Should I overwrite it?").should === true

      $stdout.should_receive(:print).with("Should I overwrite it? ")
        $stdin.should_receive(:gets).and_return('Yes')
      shell.no?("Should I overwrite it?").should === false
    end
  end

  describe "#say" do
    it "prints a message to the user" do
      $stdout.should_receive(:puts).with("Running...")
      shell.say("Running...")
    end

    it "prints a message to the user without new line if it ends with a whitespace" do
      $stdout.should_receive(:print).with("Running... ")
      shell.say("Running... ")
    end

    it "prints a message to the user without new line" do
      $stdout.should_receive(:print).with("Running...")
      shell.say("Running...", nil, false)
    end
  end

  describe "#say_status" do
    it "prints a message to the user with status" do
      $stdout.should_receive(:puts).with("      create  ~/.thor/task.thor")
      shell.say_status(:create, "~/.thor/task.thor")
    end

    it "always use new line" do
      $stdout.should_receive(:puts).with("      create  ")
      shell.say_status(:create, "")
    end

    it "does not print a message if base is muted" do
      shell.should_receive(:mute?).and_return(true)
      $stdout.should_not_receive(:puts)

      shell.mute do
        shell.say_status(:created, "~/.thor/task.thor")
      end
    end

    it "does not print a message if base is set to quiet" do
      base = MyCounter.new [1,2]
      base.should_receive(:options).and_return(:quiet => true)

      $stdout.should_not_receive(:puts)
      shell.base = base
      shell.say_status(:created, "~/.thor/task.thor")
    end

    it "does not print a message if log status is set to false" do
      $stdout.should_not_receive(:puts)
      shell.say_status(:created, "~/.thor/task.thor", false)
    end

    it "uses padding to set messages left margin" do
      shell.padding = 2
      $stdout.should_receive(:puts).with("      create      ~/.thor/task.thor")
      shell.say_status(:create, "~/.thor/task.thor")
    end
  end

  describe "#print_in_columns" do
    before do
      @array = [1234567890]
      @array += ('a'..'e').to_a
    end

    it "prints in columns" do
      content = capture(:stdout){ shell.print_in_columns(@array) }
      content.rstrip.should == "1234567890  a           b           c           d           e"
    end
  end

  describe "#print_table" do
    before do
      @table = []
      @table << ["abc", "#123", "first three"]
      @table << ["", "#0", "empty"]
      @table << ["xyz", "#786", "last three"]
    end

    it "prints a table" do
      content = capture(:stdout){ shell.print_table(@table) }
      content.should == <<-TABLE
abc  #123  first three
     #0    empty
xyz  #786  last three
TABLE
    end

    it "prints a table with indentation" do
      content = capture(:stdout){ shell.print_table(@table, :indent => 2) }
      content.should == <<-TABLE
  abc  #123  first three
       #0    empty
  xyz  #786  last three
TABLE
    end

    it "uses maximum terminal width" do
      @table << ["def", "#456", "Lançam foo bar"]
      @table << ["ghi", "#789", "بالله  عليكم"]
      shell.should_receive(:terminal_width).and_return(20)
      content = capture(:stdout){ shell.print_table(@table, :indent => 2, :truncate => true) }
      content.should == <<-TABLE
  abc  #123  firs...
       #0    empty
  xyz  #786  last...
  def  #456  Lanç...
  ghi  #789  بالل...
TABLE
    end

    it "honors the colwidth option" do
      content = capture(:stdout){ shell.print_table(@table, :colwidth => 10)}
      content.should == <<-TABLE
abc         #123  first three
            #0    empty
xyz         #786  last three
TABLE
    end

    it "prints tables with implicit columns" do
      2.times { @table.first.pop }
      content = capture(:stdout){ shell.print_table(@table) }
      content.should == <<-TABLE
abc  
     #0    empty
xyz  #786  last three
TABLE
    end

    it "prints a table with small numbers and right-aligns them" do
      table = [
        ["Name", "Number", "Color"],
        ["Erik", 1, "green"]
      ]
      content = capture(:stdout){ shell.print_table(table) }
      content.should == <<-TABLE
Name  Number  Color
Erik       1  green
TABLE
    end

    it "doesn't output extra spaces for right-aligned columns in the last column" do
      table = [
        ["Name", "Number"],
        ["Erik", 1]
      ]
      content = capture(:stdout){ shell.print_table(table) }
      content.should == <<-TABLE
Name  Number
Erik       1
TABLE
    end

    it "prints a table with big numbers" do
      table = [
        ["Name", "Number", "Color"],
        ["Erik", 1234567890123, "green"]
      ]
      content = capture(:stdout){ shell.print_table(table) }
      content.should == <<-TABLE
Name  Number         Color
Erik  1234567890123  green
TABLE
    end
  end

  describe "#file_collision" do
    it "shows a menu with options" do
      $stdout.should_receive(:print).with('Overwrite foo? (enter "h" for help) [Ynaqh] ')
      $stdin.should_receive(:gets).and_return('n')
      shell.file_collision('foo')
    end

    it "returns true if the user choose default option" do
      $stdout.stub!(:print)
      $stdin.should_receive(:gets).and_return('')
      shell.file_collision('foo').should be_true
    end

    it "returns false if the user choose no" do
      $stdout.stub!(:print)
      $stdin.should_receive(:gets).and_return('n')
      shell.file_collision('foo').should be_false
    end

    it "returns true if the user choose yes" do
      $stdout.stub!(:print)
      $stdin.should_receive(:gets).and_return('y')
      shell.file_collision('foo').should be_true
    end

    it "shows help usage if the user choose help" do
      $stdout.stub!(:print)
      $stdin.should_receive(:gets).and_return('h')
      $stdin.should_receive(:gets).and_return('n')
      help = capture(:stdout){ shell.file_collision('foo') }
      help.should =~ /h \- help, show this help/
    end

    it "quits if the user choose quit" do
      $stdout.stub!(:print)
      $stdout.should_receive(:puts).with('Aborting...')
      $stdin.should_receive(:gets).and_return('q')

      lambda {
        shell.file_collision('foo')
      }.should raise_error(SystemExit)
    end

    it "always returns true if the user choose always" do
      $stdout.should_receive(:print).with('Overwrite foo? (enter "h" for help) [Ynaqh] ')
      $stdin.should_receive(:gets).and_return('a')

      shell.file_collision('foo').should be_true

      $stdout.should_not_receive(:print)
      shell.file_collision('foo').should be_true
    end

    describe "when a block is given" do
      it "displays diff options to the user" do
        $stdout.should_receive(:print).with('Overwrite foo? (enter "h" for help) [Ynaqdh] ')
        $stdin.should_receive(:gets).and_return('s')
        shell.file_collision('foo'){ }
      end

      it "invokes the diff command" do
        $stdout.stub!(:print)
        $stdin.should_receive(:gets).and_return('d')
        $stdin.should_receive(:gets).and_return('n')
        shell.should_receive(:system).with(/diff -u/)
        capture(:stdout){ shell.file_collision('foo'){ } }
      end
    end
  end
end
