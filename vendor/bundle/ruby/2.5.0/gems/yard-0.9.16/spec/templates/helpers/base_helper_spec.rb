# frozen_string_literal: true

RSpec.describe YARD::Templates::Helpers::BaseHelper do
  include YARD::Templates::Helpers::BaseHelper

  describe "#run_verifier" do
    it "runs verifier proc against list if provided" do
      mock = Verifier.new
      expect(mock).to receive(:call).with(1)
      expect(mock).to receive(:call).with(2)
      expect(mock).to receive(:call).with(3)
      expect(self).to receive(:options).at_least(1).times.and_return(Options.new.update(:verifier => mock))
      run_verifier [1, 2, 3]
    end

    it "prunes list if lambda returns false and only false" do
      mock = Verifier.new
      expect(self).to receive(:options).at_least(1).times.and_return(Options.new.update(:verifier => mock))
      expect(mock).to receive(:call).with(1).and_return(false)
      expect(mock).to receive(:call).with(2).and_return(true)
      expect(mock).to receive(:call).with(3).and_return(nil)
      expect(mock).to receive(:call).with(4).and_return("value")
      expect(run_verifier([1, 2, 3, 4])).to eq [2, 3, 4]
    end

    it "returns list if no verifier exists" do
      expect(self).to receive(:options).at_least(1).times.and_return(Options.new)
      expect(run_verifier([1, 2, 3])).to eq [1, 2, 3]
    end
  end

  describe "#h" do
    it "returns just the text" do
      expect(h("hello world")).to eq "hello world"
      expect(h(nil)).to eq nil
    end
  end

  describe "#link_object" do
    it "returns the title if provided" do
      expect(link_object(1, "title")).to eq "title"
      expect(link_object(Registry.root, "title")).to eq "title"
    end

    it "returns a path if argument is a Proxy or object" do
      expect(link_object(Registry.root)).to eq "Top Level Namespace"
      expect(link_object(P("Array"))).to eq "Array"
    end

    it "returns path of Proxified object if argument is a String or Symbol" do
      expect(link_object("Array")).to eq "Array"
      expect(link_object(:"A::B")).to eq "A::B"
    end

    it "returns the argument if not an object, proxy, String or Symbol" do
      expect(link_object(1)).to eq 1
    end
  end

  describe "#link_url" do
    it "returns the URL" do
      expect(link_url("http://url")).to eq "http://url"
    end
  end

  describe "#linkify" do
    let(:object) { Registry.root }
    # before do
    #   stub!(:object).and_return(Registry.root)
    # end

    it "calls #link_url for mailto: links" do
      expect(self).to receive(:link_url)
      linkify("mailto:steve@example.com")
    end

    it "calls #link_url for URL schemes (http://)" do
      expect(self).to receive(:link_url)
      linkify("http://example.com")
    end

    it "calls #link_file for file: links" do
      expect(self).to receive(:link_file).with('Filename', nil, 'anchor')
      linkify("file:Filename#anchor")
    end

    it "passes off to #link_object if argument is an object" do
      obj = CodeObjects::NamespaceObject.new(nil, :YARD)
      expect(self).to receive(:link_object).with(obj)
      linkify obj
    end

    it "returns empty string and warn if object does not exist" do
      expect(log).to receive(:warn).with(/Cannot find object .* for inclusion/)
      expect(linkify('include:NotExist')).to eq ''
    end

    it "passes off to #link_url if argument is recognized as a URL" do
      url = "http://yardoc.org/"
      expect(self).to receive(:link_url).with(url, nil, :target => '_parent')
      linkify url
    end

    it "calls #link_include_object for include:ObjectName" do
      obj = CodeObjects::NamespaceObject.new(:root, :Foo)
      expect(self).to receive(:link_include_object).with(obj)
      linkify 'include:Foo'
    end

    it "calls #link_include_file for include:file:path/to/file" do
      expect(File).to receive(:file?).with('path/to/file').and_return(true)
      expect(File).to receive(:read).with('path/to/file').and_return('FOO')
      expect(linkify('include:file:path/to/file')).to eq 'FOO'
    end

    it "does not allow include:file for path above pwd" do
      expect(log).to receive(:warn).with("Cannot include file from path `a/b/../../../../file'")
      expect(linkify('include:file:a/b/../../../../file')).to eq ''
    end

    it "warns if include:file:path does not exist" do
      expect(log).to receive(:warn).with(/Cannot find file .+ for inclusion/)
      expect(linkify('include:file:notexist')).to eq ''
    end
  end

  describe "#format_types" do
    it "returns the list of types separated by commas surrounded by brackets" do
      expect(format_types(['a', 'b', 'c'])).to eq '(a, b, c)'
    end

    it "returns the list of types without brackets if brackets=false" do
      expect(format_types(['a', 'b', 'c'], false)).to eq 'a, b, c'
    end

    it "returns an empty string if list is empty or nil" do
      expect(format_types(nil)).to eq ""
      expect(format_types([])).to eq ""
    end
  end

  describe "#format_object_type" do
    it "returns Exception if type is Exception" do
      obj = double(:object, :is_exception? => true)
      allow(obj).to receive(:is_a?) {|arg| arg == YARD::CodeObjects::ClassObject }
      expect(format_object_type(obj)).to eq "Exception"
    end

    it "returns Class if type is Class" do
      obj = double(:object, :is_exception? => false)
      allow(obj).to receive(:is_a?) {|arg| arg == YARD::CodeObjects::ClassObject }
      expect(format_object_type(obj)).to eq "Class"
    end

    it "returns object type in other cases" do
      obj = double(:object, :type => "value")
      expect(format_object_type(obj)).to eq "Value"
    end
  end

  describe "#format_object_title" do
    it "returns Top Level Namespace for root object" do
      expect(format_object_title(Registry.root)).to eq "Top Level Namespace"
    end

    it "returns 'type: title' in other cases" do
      obj = double(:object, :type => :class, :title => "A::B::C")
      expect(format_object_title(obj)).to eq "Class: A::B::C"
    end
  end
end
