class Pry
  class Command::Ri < Pry::ClassCommand
    match 'ri'
    group 'Introspection'
    description 'View ri documentation.'

    banner <<-'BANNER'
      Usage: ri [spec]

      View ri documentation. Relies on the "rdoc" gem being installed.
      See also "show-doc" command.

      ri Array#each
    BANNER

    def process(spec)
      unless spec
        return output.puts "Please provide a class, module, or method name (e.g: ri Array#push)"
      end

      # Lazily load RI
      require 'rdoc/ri/driver'

      unless defined? RDoc::RI::PryDriver

        # Subclass RI so that it formats its output nicely, and uses `lesspipe`.
        subclass = Class.new(RDoc::RI::Driver) # the hard way.

        subclass.class_eval do
          def initialize(pager, opts)
            @pager = pager
            super opts
          end
          def page
            paging_text = StringIO.new
            yield paging_text
            @pager.page(paging_text.string)
          end

          def formatter(io)
            if @formatter_klass
              @formatter_klass.new
            else
              RDoc::Markup::ToAnsi.new
            end
          end
        end

        RDoc::RI.const_set :PryDriver, subclass   # hook it up!
      end

      # Spin-up an RI insance.
      ri = RDoc::RI::PryDriver.new _pry_.pager, :use_stdout => true, :interactive => false

      begin
        ri.display_names [spec]  # Get the documentation (finally!)
      rescue RDoc::RI::Driver::NotFoundError => e
        output.puts "error: '#{e.name}' not found"
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::Ri)
end
