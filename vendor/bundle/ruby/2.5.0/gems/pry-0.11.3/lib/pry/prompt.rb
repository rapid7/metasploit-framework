class Pry::Prompt
  MAP = {
    "default" => {
      value: Pry::DEFAULT_PROMPT,
      description: "The default Pry prompt. Includes information about the\n" \
                   "current expression number, evaluation context, and nesting\n" \
                   "level, plus a reminder that you're using Pry."
    },

    "simple" => {
      value: Pry::SIMPLE_PROMPT,
      description: "A simple '>>'."
    },

    "nav" => {
      value: Pry::NAV_PROMPT,
      description: "A prompt that displays the binding stack as a path and\n" \
                   "includes information about _in_ and _out_."
    },

    "none" => {
      value: Pry::NO_PROMPT,
      description: "Wave goodbye to the Pry prompt."
    }
 }
end
