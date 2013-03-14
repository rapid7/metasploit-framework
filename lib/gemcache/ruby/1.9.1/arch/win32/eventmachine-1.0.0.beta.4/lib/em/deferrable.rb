#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 16 Jul 2006
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
# 

module EventMachine
  module Deferrable
    autoload :Pool, 'em/deferrable/pool'

    # Specify a block to be executed if and when the Deferrable object receives
    # a status of :succeeded. See #set_deferred_status for more information.
    #
    # Calling this method on a Deferrable object whose status is not yet known
    # will cause the callback block to be stored on an internal list.
    # If you call this method on a Deferrable whose status is :succeeded, the
    # block will be executed immediately, receiving the parameters given to the
    # prior #set_deferred_status call.
    #
    #--
    # If there is no status, add a callback to an internal list.
    # If status is succeeded, execute the callback immediately.
    # If status is failed, do nothing.
    #
    def callback &block
      return unless block
      @deferred_status ||= :unknown
      if @deferred_status == :succeeded
        block.call(*@deferred_args)
      elsif @deferred_status != :failed
        @callbacks ||= []
        @callbacks.unshift block # << block
      end
      self
    end

    # Cancels an outstanding callback to &block if any. Undoes the action of #callback.
    #
    def cancel_callback block
      @callbacks ||= []
      @callbacks.delete block
    end

    # Specify a block to be executed if and when the Deferrable object receives
    # a status of :failed. See #set_deferred_status for more information.
    #--
    # If there is no status, add an errback to an internal list.
    # If status is failed, execute the errback immediately.
    # If status is succeeded, do nothing.
    #
    def errback &block
      return unless block
      @deferred_status ||= :unknown
      if @deferred_status == :failed
        block.call(*@deferred_args)
      elsif @deferred_status != :succeeded
        @errbacks ||= []
        @errbacks.unshift block # << block
      end
      self
    end

    # Cancels an outstanding errback to &block if any. Undoes the action of #errback.
    #
    def cancel_errback block
      @errbacks ||= []
      @errbacks.delete block
    end

    # Sets the "disposition" (status) of the Deferrable object. See also the large set of
    # sugarings for this method.
    # Note that if you call this method without arguments,
    # no arguments will be passed to the callback/errback.
    # If the user has coded these with arguments, then the
    # user code will throw an argument exception.
    # Implementors of deferrable classes <b>must</b>
    # document the arguments they will supply to user callbacks.
    #
    # OBSERVE SOMETHING VERY SPECIAL here: you may call this method even
    # on the INSIDE of a callback. This is very useful when a previously-registered
    # callback wants to change the parameters that will be passed to subsequently-registered
    # ones.
    #
    # You may give either :succeeded or :failed as the status argument.
    #
    # If you pass :succeeded, then all of the blocks passed to the object using the #callback
    # method (if any) will be executed BEFORE the #set_deferred_status method returns. All of the blocks
    # passed to the object using #errback will be discarded.
    #
    # If you pass :failed, then all of the blocks passed to the object using the #errback
    # method (if any) will be executed BEFORE the #set_deferred_status method returns. All of the blocks
    # passed to the object using # callback will be discarded.
    #
    # If you pass any arguments to #set_deferred_status in addition to the status argument,
    # they will be passed as arguments to any callbacks or errbacks that are executed.
    # It's your responsibility to ensure that the argument lists specified in your callbacks and
    # errbacks match the arguments given in calls to #set_deferred_status, otherwise Ruby will raise
    # an ArgumentError.
    #
    #--
    # We're shifting callbacks off and discarding them as we execute them.
    # This is valid because by definition callbacks are executed no more than
    # once. It also has the magic effect of permitting recursive calls, which
    # means that a callback can call #set_deferred_status and change the parameters
    # that will be sent to subsequent callbacks down the chain.
    #
    # Changed @callbacks and @errbacks from push/shift to unshift/pop, per suggestion
    # by Kirk Haines, to work around the memory leak bug that still exists in many Ruby
    # versions.
    #
    # Changed 15Sep07: after processing callbacks or errbacks, CLEAR the other set of
    # handlers. This gets us a little closer to the behavior of Twisted's "deferred,"
    # which only allows status to be set once. Prior to making this change, it was possible
    # to "succeed" a Deferrable (triggering its callbacks), and then immediately "fail" it,
    # triggering its errbacks! That is clearly undesirable, but it's just as undesirable
    # to raise an exception is status is set more than once on a Deferrable. The latter
    # behavior would invalidate the idiom of resetting arguments by setting status from
    # within a callback or errback, but more seriously it would cause spurious errors
    # if a Deferrable was timed out and then an attempt was made to succeed it. See the
    # comments under the new method #timeout.
    #
    def set_deferred_status status, *args
      cancel_timeout
      @errbacks ||= nil
      @callbacks ||= nil
      @deferred_status = status
      @deferred_args = args
      case @deferred_status
      when :succeeded
        if @callbacks
          while cb = @callbacks.pop
            cb.call(*@deferred_args)
          end
        end
        @errbacks.clear if @errbacks
      when :failed
        if @errbacks
          while eb = @errbacks.pop
            eb.call(*@deferred_args)
          end
        end
        @callbacks.clear if @callbacks
      end
    end


    # Setting a timeout on a Deferrable causes it to go into the failed state after
    # the Timeout expires (passing no arguments to the object's errbacks).
    # Setting the status at any time prior to a call to the expiration of the timeout
    # will cause the timer to be cancelled.
    def timeout seconds, *args
      cancel_timeout
      me = self
      @deferred_timeout = EventMachine::Timer.new(seconds) {me.fail(*args)}
      self
    end

    # Cancels an outstanding timeout if any. Undoes the action of #timeout.
    #
    def cancel_timeout
      @deferred_timeout ||= nil
      if @deferred_timeout
        @deferred_timeout.cancel
        @deferred_timeout = nil
      end
    end


    # Sugar for set_deferred_status(:succeeded, ...)
    #
    def succeed *args
      set_deferred_status :succeeded, *args
    end
    alias set_deferred_success succeed

    # Sugar for set_deferred_status(:failed, ...)
    #
    def fail *args
      set_deferred_status :failed, *args
    end
    alias set_deferred_failure fail
  end


  # DefaultDeferrable is an otherwise empty class that includes Deferrable.
  # This is very useful when you just need to return a Deferrable object
  # as a way of communicating deferred status to some other part of a program.
  class DefaultDeferrable
    include Deferrable
  end
end