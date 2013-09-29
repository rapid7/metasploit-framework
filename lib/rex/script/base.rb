# -*- coding: binary -*-
module Rex
module Script
class Base

  class OutputSink
    def print(msg); end
    def print_line(msg); end
    def print_status(msg); end
    def print_good(msg); end
    def print_error(msg); end
    def print_warning(msg); end
  end

  attr_accessor :client, :framework, :path, :error, :args
  attr_accessor :session, :sink, :workspace

  def initialize(client, path)
    self.client    = client
    self.framework = client.framework
    self.path      = path
    self.sink      = OutputSink.new

    client.framework.db.with_connection do
      self.workspace = client.framework.db.find_workspace( client.workspace.to_s ) || client.framework.db.workspace
    end

    # Convenience aliases
    self.session   = self.client
  end

  def output
    client.user_output || self.sink
  end

  def completed
    raise Rex::Script::Completed
  end

  def run(args=[])
    self.args = args = args.flatten
    begin
      eval(::File.read(self.path, ::File.size(self.path)), binding )
    rescue ::Interrupt
    rescue ::Rex::Script::Completed
    rescue ::Exception => e
      self.error = e
      raise e
    end
  end

  def print(*args);         output.print(*args);          end
  def print_status(*args);  output.print_status(*args);   end
  def print_error(*args);   output.print_error(*args);    end
  def print_good(*args);    output.print_good(*args);     end
  def print_line(*args);    output.print_line(*args);     end

end
end
end

