###
### $Release: 2.7.0 $
### copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
###

require  "#{File.dirname(__FILE__)}/test.rb"


class KwarkUsersGuideTest < Test::Unit::TestCase

  DIR = File.expand_path(File.dirname(__FILE__) + '/data/users-guide')
  CWD = Dir.pwd()


  def setup
    Dir.chdir DIR
  end


  def teardown
    Dir.chdir CWD
  end


  def _test
    @name = (caller()[0] =~ /`(.*?)'/) && $1
    s = File.read(@filename)
    s =~ /\A\$ (.*?)\n/
    command = $1
    expected = $'
    if ruby19?
      case @name
      when 'test_main_program1_result'
        expected.sub!('["eruby", "items", "x", "_buf"]', '[:_buf, :eruby, :items, :x]')
      when 'test_main_program2_result'
        expected.sub!('["_context", "x", "_buf"]', '[:_buf, :x, :_context]')
      end
    elsif rubinius?
      command.sub!(/^ruby\b/, 'rbx')
      case @name
      when 'test_main_program1_result'
        expected.sub!('["eruby", "items", "x", "_buf"]', '["_buf", "eruby", "items", "x"]')
      when 'test_main_program2_result'
        expected.sub!('["_context", "x", "_buf"]', '["_buf", "x", "_context"]')
      end
    end
    result = `#{command}`
    assert_text_equal(expected, result)
  end


  Dir.chdir DIR do
    filenames = []
    filenames += Dir.glob('*.result')
    filenames += Dir.glob('*.source')
    filenames.each do |filename|
      name = filename.gsub(/[^\w]/, '_')
      s = <<-END
        def test_#{name}
          # $stderr.puts "*** debug: test_#{name}"
          @name = '#{name}'
          @filename = '#{filename}'
          _test()
        end
      END
      eval s
    end
  end


  self.post_definition()

end
