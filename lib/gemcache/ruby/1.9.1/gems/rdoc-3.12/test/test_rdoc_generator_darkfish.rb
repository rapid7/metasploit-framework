require 'rdoc/test_case'

class TestRDocGeneratorDarkfish < RDoc::TestCase

  def setup
    super

    @lib_dir = "#{@pwd}/lib"
    $LOAD_PATH.unshift @lib_dir # ensure we load from this RDoc

    @options = RDoc::Options.new
    @options.option_parser = OptionParser.new

    @tmpdir = File.join Dir.tmpdir, "test_rdoc_generator_darkfish_#{$$}"
    FileUtils.mkdir_p @tmpdir
    Dir.chdir @tmpdir
    @options.op_dir = @tmpdir
    @options.generator = RDoc::Generator::Darkfish

    $LOAD_PATH.each do |path|
      darkfish_dir = File.join path, 'rdoc/generator/template/darkfish/'
      next unless File.directory? darkfish_dir
      @options.template_dir = darkfish_dir
      break
    end

    rd = RDoc::RDoc.new
    rd.options = @options
    RDoc::RDoc.current = rd

    @g = @options.generator.new @options

    rd.generator = @g

    @top_level = RDoc::TopLevel.new 'file.rb'
    @top_level.parser = RDoc::Parser::Ruby
    @klass = @top_level.add_class RDoc::NormalClass, 'Object'

    @meth = RDoc::AnyMethod.new nil, 'method'
    @meth_bang = RDoc::AnyMethod.new nil, 'method!'
    @attr = RDoc::Attr.new nil, 'attr', 'RW', ''

    @klass.add_method @meth
    @klass.add_method @meth_bang
    @klass.add_attribute @attr

    @ignored = @top_level.add_class RDoc::NormalClass, 'Ignored'
    @ignored.ignore
  end

  def teardown
    super

    $LOAD_PATH.shift
    Dir.chdir @pwd
    FileUtils.rm_rf @tmpdir
  end

  def assert_file path
    assert File.file?(path), "#{path} is not a file"
  end

  def refute_file path
    refute File.exist?(path), "#{path} exists"
  end

  def test_generate
    top_level = RDoc::TopLevel.new 'file.rb'
    top_level.add_class @klass.class, @klass.name

    @g.generate [top_level]

    assert_file 'index.html'
    assert_file 'Object.html'
    assert_file 'table_of_contents.html'
    assert_file 'js/search_index.js'

    encoding = if Object.const_defined? :Encoding then
                 Regexp.escape Encoding.default_external.name
               else
                 Regexp.escape 'UTF-8'
               end

    assert_match(/<meta content="text\/html; charset=#{encoding}"/,
                 File.read('index.html'))
    assert_match(/<meta content="text\/html; charset=#{encoding}"/,
                 File.read('Object.html'))

    refute_match(/Ignored/, File.read('index.html'))
  end

  def test_generate_dry_run
    @options.dry_run = true
    top_level = RDoc::TopLevel.new 'file.rb'
    top_level.add_class @klass.class, @klass.name

    @g.generate [top_level]

    refute_file 'index.html'
    refute_file 'Object.html'
  end

  def test_generate_static
    FileUtils.mkdir_p 'dir/images'
    FileUtils.touch 'dir/images/image.png'
    FileUtils.mkdir_p 'file'
    FileUtils.touch 'file/file.txt'

    @options.static_path = [
      File.expand_path('dir'),
      File.expand_path('file/file.txt'),
    ]

    @g.generate [@top_level]

    assert_file 'images/image.png'
    assert_file 'file.txt'
  end

  def test_generate_static_dry_run
    FileUtils.mkdir 'static'
    FileUtils.touch 'static/image.png'

    @options.static_path = [File.expand_path('static')]
    @options.dry_run = true

    @g.generate [@top_level]

    refute_file 'image.png'
  end

  def test_template_for
    classpage = Pathname.new @options.template_dir + 'class.rhtml'

    template = @g.send(:template_for, classpage)
    assert_kind_of RDoc::ERBIO, template

    assert_same template, @g.send(:template_for, classpage)
  end

  def test_template_for_dry_run
    classpage = Pathname.new @options.template_dir + 'class.rhtml'

    template = @g.send(:template_for, classpage)
    assert_kind_of ERB, template

    assert_same template, @g.send(:template_for, classpage)
  end

end

