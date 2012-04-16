# $Id$

require 'test/unit'

module EmTestRunner
  @em_root = File.expand_path(File.dirname(__FILE__) + '/../')
  @lib_dir = File.join(@em_root, 'lib')
  @ext_dir = File.join(@em_root, 'ext')
  @java_dir = File.join(@em_root, 'java')

  def self.run(glob = 'test_*.rb')
    $:.unshift(@lib_dir)
    $:.unshift(@ext_dir)
    $:.unshift(@java_dir)

    case glob
    when Array
      files = glob
    else
      files = Dir[File.dirname(__FILE__) + '/' + glob]
    end

    files.each do |tc|
      require tc
    end
  end
end

if __FILE__ == $0
  EmTestRunner.run
end
