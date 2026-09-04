# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Post
    module Meterpreter
      #
      # Pure-function helpers for async meterpreter's work-hour / work-day
      # window. Extracted from Client so the math can be unit-tested without
      # loading the full meterpreter dependency graph.
      #
      module AsyncWindow
        MAXIMUM_GAP = 7 * 86400

        # Seconds until the next allowed poll window opens, given the current
        # async work-hour config and a target-local "now" (a Time whose #hour
        # and #wday read in the target's local frame — typically produced by
        # Client#target_time_now).
        #
        # Returns 0 when polling is currently permitted (inside the window on
        # a work day) or when the config is fully permissive. A zero work-day
        # mask means all days, matching the target-side compatibility behavior.
        # Equal start/end hours represent a full-day window. Overnight windows
        # (for example 22-6) are supported.
        #
        # @param now [Time] target-local wall clock
        # @param work_start [Integer] window start hour, 0-23
        # @param work_end   [Integer] window end hour, 1-24 (exclusive upper bound)
        # @param work_days  [Integer] bitmask, bit0=Sun..bit6=Sat
        # @return [Integer] seconds
        def self.seconds_until_next_window(now, work_start, work_end, work_days)
          work_start = work_start.to_i
          work_end = work_end.to_i
          work_days = work_days.to_i & 0x7F
          work_days = 0x7F if work_days == 0

          return 0 if work_days == 0x7F && (work_start == work_end || (work_start <= 0 && work_end >= 24))

          hour = now.hour
          wday = now.wday # 0=Sun..6=Sat
          return 0 if allowed?(hour, wday, work_start, work_end, work_days)

          # Walk forward one hour at a time from the top of the next hour.
          # Bounded by 7 days, so this loop is trivially finite.
          delta = 3600 - (now.min * 60 + now.sec)
          probe_hour = (hour + 1) % 24
          probe_wday = wday + ((hour + 1) / 24)

          while delta < MAXIMUM_GAP
            wd = probe_wday % 7
            return delta if allowed?(probe_hour, wd, work_start, work_end, work_days)

            delta += 3600
            probe_hour = (probe_hour + 1) % 24
            probe_wday += 1 if probe_hour == 0
          end
          MAXIMUM_GAP
        end

        def self.allowed?(hour, wday, work_start, work_end, work_days)
          return true if work_start == work_end

          if work_start < work_end
            (work_days & (1 << wday)) != 0 && hour >= work_start && hour < work_end
          elsif hour >= work_start
            (work_days & (1 << wday)) != 0
          elsif hour < work_end
            (work_days & (1 << ((wday - 1) % 7))) != 0
          else
            false
          end
        end
      end
    end
  end
end
