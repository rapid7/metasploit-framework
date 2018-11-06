module Pry::Config::Convenience
  SHORTCUTS = [
               :input,
               :output,
               :commands,
               :print,
               :exception_handler,
               :hooks,
               :color,
               :pager,
               :editor,
               :memory_size,
               :extra_sticky_locals
              ]


  def config_shortcut(*names)
    names.each do |name|
      reader = name
      setter = "#{name}="
      define_method(reader) { config.public_send(name) }
      define_method(setter) { |value| config.public_send(setter, value) }
    end
  end
end
