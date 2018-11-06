module Pry::Testable::Mockable
  def mock_command(cmd, args=[], opts={})
    output = StringIO.new
    pry = Pry.new(output: output)
    ret = cmd.new(opts.merge(pry_instance: pry, :output => output)).call_safely(*args)
    Struct.new(:output, :return).new(output.string, ret)
  end

  def mock_exception(*mock_backtrace)
    StandardError.new.tap do |e|
      e.define_singleton_method(:backtrace) { mock_backtrace }
    end
  end
end
