require 'pry/commands/ls/grep'
require 'pry/commands/ls/formatter'
require 'pry/commands/ls/globals'
require 'pry/commands/ls/constants'
require 'pry/commands/ls/methods'
require 'pry/commands/ls/self_methods'
require 'pry/commands/ls/instance_vars'
require 'pry/commands/ls/local_names'
require 'pry/commands/ls/local_vars'

class Pry
  class Command::Ls < Pry::ClassCommand

    class LsEntity
      attr_reader :_pry_

      def initialize(opts)
        @interrogatee = opts[:interrogatee]
        @no_user_opts = opts[:no_user_opts]
        @opts = opts[:opts]
        @args = opts[:args]
        @grep = Grep.new(Regexp.new(opts[:opts][:G] || '.'))
        @_pry_ = opts.delete(:_pry_)
      end

      def entities_table
        entities.map(&:write_out).reject { |o| !o }.join('')
      end

      private

      def grep(entity)
        entity.tap { |o| o.grep = @grep }
      end

      def globals
        grep Globals.new(@opts, _pry_)
      end

      def constants
        grep Constants.new(@interrogatee, @no_user_opts, @opts, _pry_)
      end

      def methods
        grep(Methods.new(@interrogatee, @no_user_opts, @opts, _pry_))
      end

      def self_methods
        grep SelfMethods.new(@interrogatee, @no_user_opts, @opts, _pry_)
      end

      def instance_vars
        grep InstanceVars.new(@interrogatee, @no_user_opts, @opts, _pry_)
      end

      def local_names
        grep LocalNames.new(@no_user_opts, @args, _pry_)
      end

      def local_vars
        LocalVars.new(@opts, _pry_)
      end

      def entities
        [globals, constants, methods, self_methods, instance_vars, local_names,
          local_vars]
      end
    end
  end
end
