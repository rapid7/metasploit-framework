# -*- ruby encoding: utf-8 -*-

require 'rubygems'
require 'pathname'
require 'psych'

if ENV['COVERALLS']
  require 'coveralls'
  Coveralls.wear!
elsif ENV['COVERAGE']
  require 'simplecov'

  def require_do(resource, &block)
    require resource
    block.call
  rescue LoadError
    nil
  end

  formatters = [ SimpleCov::Formatter::HTMLFormatter ]

  require_do('simplecov-rcov') {
    formatters << SimpleCov::Formatter::RcovFormatter
  }
  require_do('simplecov-vim/formatter') {
    formatters << SimpleCov::Formatter::VimFormatter
  }
  require_do('simplecov-sublime-ruby-coverage') {
    formatters << SimpleCov::Formatter::SublimeRubyCoverageFormatter
  }

  SimpleCov.start do
    formatter SimpleCov::Formatter::MultiFormatter[*formatters]
  end
end

file   = Pathname.new(__FILE__).expand_path
path   = file.parent
parent = path.parent

$:.unshift parent.join('lib')

require 'diff-lcs'

module Diff::LCS::SpecHelper
  def hello
    "hello"
  end

  def hello_ary
    %W(h e l l o)
  end

  def seq1
    %w(a b c e h j l m n p)
  end

  def skipped_seq1
    %w(a h n p)
  end

  def seq2
    %w(b c d e f j k l m r s t)
  end

  def skipped_seq2
    %w(d f k r s t)
  end

  def word_sequence
    %w(abcd efgh ijkl mnopqrstuvwxyz)
  end

  def correct_lcs
    %w(b c e j l m)
  end

  def correct_forward_diff
    [
      [ [ '-',  0, 'a' ] ],
      [ [ '+',  2, 'd' ] ],
      [ [ '-',  4, 'h' ],
        [ '+',  4, 'f' ] ],
      [ [ '+',  6, 'k' ] ],
      [ [ '-',  8, 'n' ],
        [ '-',  9, 'p' ],
        [ '+',  9, 'r' ],
        [ '+', 10, 's' ],
        [ '+', 11, 't' ] ]
    ]
  end

  def correct_backward_diff
    [
      [ [ '+',  0, 'a' ] ],
      [ [ '-',  2, 'd' ] ],
      [ [ '-',  4, 'f' ],
        [ '+',  4, 'h' ] ],
      [ [ '-',  6, 'k' ] ],
      [
        [ '-',  9, 'r' ],
        [ '-', 10, 's' ],
        [ '+',  8, 'n' ],
        [ '-', 11, 't' ],
        [ '+',  9, 'p' ] ]
    ]
  end

  def correct_forward_sdiff
    [
      [ '-', [  0, 'a' ], [  0, nil ] ],
      [ '=', [  1, 'b' ], [  0, 'b' ] ],
      [ '=', [  2, 'c' ], [  1, 'c' ] ],
      [ '+', [  3, nil ], [  2, 'd' ] ],
      [ '=', [  3, 'e' ], [  3, 'e' ] ],
      [ '!', [  4, 'h' ], [  4, 'f' ] ],
      [ '=', [  5, 'j' ], [  5, 'j' ] ],
      [ '+', [  6, nil ], [  6, 'k' ] ],
      [ '=', [  6, 'l' ], [  7, 'l' ] ],
      [ '=', [  7, 'm' ], [  8, 'm' ] ],
      [ '!', [  8, 'n' ], [  9, 'r' ] ],
      [ '!', [  9, 'p' ], [ 10, 's' ] ],
      [ '+', [ 10, nil ], [ 11, 't' ] ]
    ]
  end

  def reverse_sdiff(forward_sdiff)
    forward_sdiff.map { |line|
      line[1], line[2] = line[2], line[1]
      case line[0]
      when '-' then line[0] = '+'
      when '+' then line[0] = '-'
      end
      line
    }
  end

  def change_diff(diff)
    map_diffs(diff, Diff::LCS::Change)
  end

  def context_diff(diff)
    map_diffs(diff, Diff::LCS::ContextChange)
  end

  def format_diffs(diffs)
    diffs.map do |e|
      if e.kind_of?(Array)
        e.map { |f| f.to_a.join }.join(", ")
      else
        e.to_a.join
      end
    end.join("\n")
  end

  def map_diffs(diffs, klass = Diff::LCS::ContextChange)
    diffs.map do |chunks|
      if klass == Diff::LCS::ContextChange
        klass.from_a(chunks)
      else
        chunks.map { |changes| klass.from_a(changes) }
      end
    end
  end

  def balanced_traversal(s1, s2, callback_type)
    callback = __send__(callback_type)
    Diff::LCS.traverse_balanced(s1, s2, callback)
    callback
  end

  def balanced_reverse(change_result)
    new_result = []
    change_result.each { |line|
      line = [ line[0], line[2], line[1] ]
      case line[0]
      when '<'
        line[0] = '>'
      when '>'
        line[0] = '<'
      end
      new_result << line
    }
    new_result.sort_by { |line| [ line[1], line[2] ] }
  end

  def map_to_no_change(change_result)
    new_result = []
    change_result.each { |line|
      case line[0]
      when '!'
        new_result << [ '<', line[1], line[2] ]
        new_result << [ '>', line[1] + 1, line[2] ]
      else
        new_result << line
      end
    }
    new_result
  end

  def simple_callback
    callbacks = Object.new
    class << callbacks
      attr_reader :matched_a
      attr_reader :matched_b
      attr_reader :discards_a
      attr_reader :discards_b
      attr_reader :done_a
      attr_reader :done_b

      def reset
        @matched_a = []
        @matched_b = []
        @discards_a = []
        @discards_b = []
        @done_a = []
        @done_b = []
      end

      def match(event)
        @matched_a << event.old_element
        @matched_b << event.new_element
      end

      def discard_b(event)
        @discards_b << event.new_element
      end

      def discard_a(event)
        @discards_a << event.old_element
      end

      def finished_a(event)
        @done_a << [event.old_element, event.old_position,
          event.new_element, event.new_position]
      end

      def finished_b(event)
        p "called #finished_b"
        @done_b << [event.old_element, event.old_position,
          event.new_element, event.new_position]
      end
    end
    callbacks.reset
    callbacks
  end

  def simple_callback_no_finishers
    simple = simple_callback
    class << simple
      undef :finished_a
      undef :finished_b
    end
    simple
  end

  def balanced_callback
    cb = Object.new
    class << cb
      attr_reader :result

      def reset
        @result = []
      end

      def match(event)
        @result << [ "=", event.old_position, event.new_position ]
      end

      def discard_a(event)
        @result << [ "<", event.old_position, event.new_position ]
      end

      def discard_b(event)
        @result << [ ">", event.old_position, event.new_position ]
      end

      def change(event)
        @result << [ "!", event.old_position, event.new_position ]
      end
    end
    cb.reset
    cb
  end

  def balanced_callback_no_change
    balanced = balanced_callback
    class << balanced
      undef :change
    end
    balanced
  end

  module Matchers
    extend RSpec::Matchers::DSL

    matcher :be_nil_or_match_values do |ii, s1, s2|
      match do |ee|
        expect(ee).to(satisfy { |vee| vee.nil? || s1[ii] == s2[ee] })
      end
    end

    matcher :correctly_map_sequence do |s1|
      match do |actual|
        actual.each_with_index { |ee, ii|
          expect(ee).to be_nil_or_match_values(ii, s1, @s2)
        }
      end

      chain :to_other_sequence do |s2|
        @s2 = s2
      end
    end
  end
end

RSpec.configure do |conf|
  conf.include Diff::LCS::SpecHelper
  conf.alias_it_should_behave_like_to :it_has_behavior, 'has behavior:'
  conf.filter_run_excluding :broken => true
end
