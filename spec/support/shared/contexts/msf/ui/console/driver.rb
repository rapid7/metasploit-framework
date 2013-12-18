shared_context 'Msf::Ui::Console::Driver' do
  include_context 'Msf::Simple::Framework'

  let(:msf_ui_console_driver) do
    msf_ui_console_driver_class.new(framework: framework)
  end

  # Have to use a dummy class because Msf::Ui::Console::Driver#initialize is too complex and does too many things
  # with side-effects. It can safely be a subclass of Msf::Ui::Driver because Msf::Ui::Driver#initialize doesn't do
  # anything
  let(:msf_ui_console_driver_class) do
    Class.new(Msf::Ui::Driver) do
      include Rex::Ui::Text::DispatcherShell

      #
      # Attributes
      #

      # @!attribute [rw] active_module
      #   @return [String, nil]
      attr_accessor :active_module


      # @!attribute [rw] framework_prompt
      #   The prompt according to the framework data store
      #
      #   @return [String, nil] Defaults to {Msf::Ui::Console::Driver::DEFAULT_PROMPT}
      attr_writer :framework_prompt

      # @!attribute [rw] framework_prompt_char
      #   The prompt characters separating the {#prompt} from user input according to the framework data store.
      #
      #   @return [String, nil] Defaults to {Msf::Ui::Console::Driver::DEFAULT_PROMPT_CHAR}
      attr_writer :framework_prompt_char

      #
      # Methods
      #

      # @!method flush
      #   Flushes {#output} buffers so they are written immediately.
      #
      #   @return [void]
      #
      # @!method tty?
      #   Whether {#output} is attached to TTY.
      #
      #   @return [true] if {#shell} is attached to a TTY.
      #   @return [false] if {#shell} is not attached to a TTY or a mix of a TTY and something other non-TTY `IO`.
      delegate :flush,
               :tty?,
               :width,
               to: :output

      def framework_prompt
        @framework_prompt ||= Msf::Ui::Console::Driver::DEFAULT_PROMPT
      end

      def framework_prompt_char
        @framework_prompt_char ||= Msf::Ui::Console::Driver::DEFAULT_PROMPT_CHAR
      end

      def initialize(attributes={})
        self.framework_prompt = attributes[:prompt]
        self.framework_prompt_char = attributes[:prompt_char]
        super(framework_prompt, framework_prompt_char, attributes[:histfile], attributes[:framework])
      end

      def output
        @output ||= Rex::Ui::Text::Output::Stdio.new
      end
    end
  end
end