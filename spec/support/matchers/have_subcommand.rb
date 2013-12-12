RSpec::Matchers.define :have_subcommand do |name|
  chain :class_name do |class_name|
    @class_name = class_name
  end

  chain :default do |default|
    @default = default
  end

  failure_message_for_should do |command|
    if @has_subcommand
      messages = []

      if !@has_class_name
        messages << "#{command.class} expected to use #{@class_name} for subcommand #{name}, but using #{@actual_class_name}"
      end

      if !@has_default
        if @default
          messages << "#{command.class} has #{@actual_default_subcommand_name} as default subcommand, but expected #{name} as the default subcommand"
        else
          messages << "#{command.class} has #{name} as default subcommand, but did not expect #{name} to be the default subcommand"
        end
      end

      messages.to_sentence
    else
      "#{command.class} should have subcommand named #{name}"
    end
  end

  match do |command|
    subcommand = command.send(:subcommand_by_name)[name]

    if subcommand
      @has_subcommand = true

      if @class_name
        @actual_class_name = subcommand.class.name

        if @actual_class_name == @class_name
          @has_class_name = true
        else
          @has_class_name = false
        end
      end

      @default ||= false
      @actual_default_subcommand_name = command.class.default_subcommand_name

      if @default
        if name == @actual_default_subcommand_name
          @has_default = true
        else
          @has_default = false
        end
      else
        if name != @actual_default_subcommand_name
          @has_default = true
        else
          @has_default = false
        end
      end
    else
      @has_subcommand = false
    end

    @has_subcommand && @has_class_name && @has_default
  end
end