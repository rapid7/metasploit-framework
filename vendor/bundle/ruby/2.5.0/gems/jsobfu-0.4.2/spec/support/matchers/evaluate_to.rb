require 'json'

RSpec::Matchers.define :evaluate_to do |expected|
  match do |observed|
    begin
      @expected_output = ExecJS.compile(expected).call('test')
    rescue ExecJS::ProgramError => e
      @example_failed = e
      @bail = true
    end

    begin
      @observed_output = ExecJS.compile(observed).call('test')
    rescue ExecJS::ProgramError => e
      @compiled_failed = e
      @bail = true
    end

    if @observed_output.nil? or @expected_output.nil?
      @output_nil = true
      @bail = true
    end

    unless @bail
      expect(@observed_output).to eq @expected_output
    end
  end

  failure_message do |observed|
    if @example_failed
      "runtime error while evaluating:\n\n#{expected}\n\n#{@example_failed}"
    elsif @compiled_failed
      "runtime error while evaluating:\n\n#{observed}\n\n#{@compiled_failed}"      
    elsif @output_nil
      "output was nil:\n\nexpected: #{@expected_output}\n\nobserved: #{@observed_output}"
    else
      "expected that the code:\n\n#{expected}:\n\n=> #{@expected_output}\n\n"+
      "evaluate to the same result as :\n\n#{observed}\n\n=> #{@observed_output}"
    end
  end
end
