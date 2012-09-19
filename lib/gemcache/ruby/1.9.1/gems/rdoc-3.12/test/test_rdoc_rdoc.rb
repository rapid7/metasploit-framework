require 'rdoc/test_case'

class TestRDocRDoc < RDoc::TestCase

  def setup
    super

    @rdoc = RDoc::RDoc.new
    @rdoc.options = RDoc::Options.new

    @stats = RDoc::Stats.new 0, 0
    @rdoc.instance_variable_set :@stats, @stats
  end

  def test_class_reset
    RDoc::RDoc.current = :junk

    tl = RDoc::TopLevel.new 'file.rb'
    tl.add_class RDoc::NormalClass, 'C'
    tl.add_class RDoc::NormalModule, 'M'

    c = RDoc::Parser::C
    enclosure_classes = c.send :class_variable_get, :@@enclosure_classes
    enclosure_classes['A'] = 'B'
    known_bodies = c.send :class_variable_get, :@@known_bodies
    known_bodies['A'] = 'B'

    RDoc::RDoc.reset

    assert_nil RDoc::RDoc.current

    assert_empty RDoc::TopLevel.all_classes_hash
    assert_empty RDoc::TopLevel.all_files_hash
    assert_empty RDoc::TopLevel.all_modules_hash

    assert_empty c.send :class_variable_get, :@@enclosure_classes
    assert_empty c.send :class_variable_get, :@@known_bodies
  end

  def test_gather_files
    file = File.expand_path __FILE__
    assert_equal [file], @rdoc.gather_files([file, file])
  end

  def test_handle_pipe
    $stdin = StringIO.new "hello"

    out, = capture_io do
      @rdoc.handle_pipe
    end

    assert_equal "\n<p>hello</p>\n", out
  ensure
    $stdin = STDIN
  end

  def test_handle_pipe_rd
    $stdin = StringIO.new "=begin\nhello\n=end"

    @rdoc.options.markup = 'rd'

    out, = capture_io do
      @rdoc.handle_pipe
    end

    assert_equal "\n<p>hello</p>\n", out
  ensure
    $stdin = STDIN
  end

  def test_load_options
    temp_dir do
      options = RDoc::Options.new
      options.markup = 'tomdoc'
      options.write_options

      options = @rdoc.load_options

      assert_equal 'tomdoc', options.markup
    end
  end

  def test_load_options_invalid
    temp_dir do
      open '.rdoc_options', 'w' do |io|
        io.write "a: !ruby.yaml.org,2002:str |\nfoo"
      end

      e = assert_raises RDoc::Error do
        @rdoc.load_options
      end

      options_file = File.expand_path '.rdoc_options'
      assert_equal "#{options_file} is not a valid rdoc options file", e.message
    end
  end

  def load_options_no_file
    temp_dir do
      options = @rdoc.load_options

      assert_kind_of RDoc::Options, options
    end
  end

  def test_normalized_file_list
    files = @rdoc.normalized_file_list [__FILE__]

    files = files.map { |file| File.expand_path file }

    assert_equal [File.expand_path(__FILE__)], files
  end

  def test_normalized_file_list_not_modified
    files = [__FILE__]

    @rdoc.last_modified[__FILE__] = File.stat(__FILE__).mtime

    files = @rdoc.normalized_file_list [__FILE__]

    assert_empty files
  end

  def test_parse_file_encoding
    skip "Encoding not implemented" unless Object.const_defined? :Encoding
    @rdoc.options.encoding = Encoding::ISO_8859_1

    Tempfile.open 'test.txt' do |io|
      io.write 'hi'
      io.rewind

      top_level = @rdoc.parse_file io.path

      assert_equal Encoding::ISO_8859_1, top_level.absolute_name.encoding
    end
  end

  def test_remove_unparseable
    file_list = %w[
      blah.class
      blah.eps
      blah.erb
      blah.scpt.txt
      blah.ttf
      blah.yml
    ]

    assert_empty @rdoc.remove_unparseable file_list
  end

  def test_remove_unparseable_tags_emacs
    temp_dir do
      open 'TAGS', 'w' do |io| # emacs
        io.write "\f\nlib/foo.rb,43\n"
      end

      file_list = %w[
        TAGS
      ]

      assert_empty @rdoc.remove_unparseable file_list
    end
  end

  def test_remove_unparseable_tags_vim
    temp_dir do
      open 'TAGS', 'w' do |io| # emacs
        io.write "!_TAG_"
      end

      file_list = %w[
        TAGS
      ]

      assert_empty @rdoc.remove_unparseable file_list
    end
  end

  def test_setup_output_dir
    Dir.mktmpdir {|d|
      path = File.join d, 'testdir'

      last = @rdoc.setup_output_dir path, false

      assert_empty last

      assert File.directory? path
      assert File.exist? @rdoc.output_flag_file path
    }
  end

  def test_setup_output_dir_dry_run
    @rdoc.options.dry_run = true

    Dir.mktmpdir do |d|
      path = File.join d, 'testdir'

      @rdoc.setup_output_dir path, false

      refute File.exist? path
    end
  end

  def test_setup_output_dir_exists
    Dir.mktmpdir {|path|
      open @rdoc.output_flag_file(path), 'w' do |io|
        io.puts Time.at 0
        io.puts "./lib/rdoc.rb\t#{Time.at 86400}"
      end

      last = @rdoc.setup_output_dir path, false

      assert_equal 1, last.size
      assert_equal Time.at(86400), last['./lib/rdoc.rb']
    }
  end

  def test_setup_output_dir_exists_empty_created_rid
    Dir.mktmpdir {|path|
      open @rdoc.output_flag_file(path), 'w' do end

      e = assert_raises RDoc::Error do
        @rdoc.setup_output_dir path, false
      end

      assert_match %r%Directory #{Regexp.escape path} already exists%, e.message
    }
  end

  def test_setup_output_dir_exists_file
    Tempfile.open 'test_rdoc_rdoc' do |tempfile|
      path = tempfile.path

      e = assert_raises RDoc::Error do
        @rdoc.setup_output_dir path, false
      end

      assert_match(%r%#{Regexp.escape path} exists and is not a directory%,
                   e.message)
    end
  end

  def test_setup_output_dir_exists_not_rdoc
    Dir.mktmpdir do |dir|
      e = assert_raises RDoc::Error do
        @rdoc.setup_output_dir dir, false
      end

      assert_match %r%Directory #{Regexp.escape dir} already exists%, e.message
    end
  end

  def test_update_output_dir
    Dir.mktmpdir do |d|
      @rdoc.update_output_dir d, Time.now, {}

      assert File.exist? "#{d}/created.rid"
    end
  end

  def test_update_output_dir_dont
    Dir.mktmpdir do |d|
      @rdoc.options.update_output_dir = false
      @rdoc.update_output_dir d, Time.now, {}

      refute File.exist? "#{d}/created.rid"
    end
  end

  def test_update_output_dir_dry_run
    Dir.mktmpdir do |d|
      @rdoc.options.dry_run = true
      @rdoc.update_output_dir d, Time.now, {}

      refute File.exist? "#{d}/created.rid"
    end
  end

end

