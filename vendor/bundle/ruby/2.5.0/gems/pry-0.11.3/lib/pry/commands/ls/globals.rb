class Pry
  class Command::Ls < Pry::ClassCommand
    class Globals < Pry::Command::Ls::Formatter

      # Taken from "puts global_variables.inspect".
      BUILTIN_GLOBALS =
        %w($" $$ $* $, $-0 $-F $-I $-K $-W $-a $-d $-i $-l $-p $-v $-w $. $/ $\\
           $: $; $< $= $> $0 $ARGV $CONSOLE $DEBUG $DEFAULT_INPUT $DEFAULT_OUTPUT
           $FIELD_SEPARATOR $FILENAME $FS $IGNORECASE $INPUT_LINE_NUMBER
           $INPUT_RECORD_SEPARATOR $KCODE $LOADED_FEATURES $LOAD_PATH $NR $OFS
           $ORS $OUTPUT_FIELD_SEPARATOR $OUTPUT_RECORD_SEPARATOR $PID $PROCESS_ID
           $PROGRAM_NAME $RS $VERBOSE $deferr $defout $stderr $stdin $stdout)

      # `$SAFE` and `$?` are thread-local, the exception stuff only works in a
      # rescue clause, everything else is basically a local variable with a `$`
      # in its name.
      PSEUDO_GLOBALS =
        %w($! $' $& $` $@ $? $+ $_ $~ $1 $2 $3 $4 $5 $6 $7 $8 $9
           $CHILD_STATUS $SAFE $ERROR_INFO $ERROR_POSITION $LAST_MATCH_INFO
           $LAST_PAREN_MATCH $LAST_READ_LINE $MATCH $POSTMATCH $PREMATCH)

      def initialize(opts, _pry_)
        super(_pry_)
        @default_switch = opts[:globals]
      end

      def output_self
        variables = format(@target.eval('global_variables'))
        output_section('global variables', grep.regexp[variables])
      end

      private

      def format(globals)
        globals.map(&:to_s).sort_by(&:downcase).map do |name|
          if PSEUDO_GLOBALS.include?(name)
            color(:pseudo_global, name)
          elsif BUILTIN_GLOBALS.include?(name)
            color(:builtin_global, name)
          else
            color(:global_var, name)
          end
        end
      end

    end
  end
end
