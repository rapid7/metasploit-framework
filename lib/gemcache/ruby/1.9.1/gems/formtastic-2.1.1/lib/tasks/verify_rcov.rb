require 'colored'

# @private
module RCov

  class VerifyTask < Rake::TaskLib

    attr_accessor :name
    attr_accessor :index_html
    attr_accessor :verbose
    attr_accessor :threshold
    attr_accessor :require_exact_threshold

    def initialize(name=:verify_rcov)
      @name = name
      @index_html = 'coverage/index.html'
      @verbose = true
      @require_exact_threshold = true
      yield self if block_given?
      raise "Threshold must be set" if @threshold.nil?
      define
    end

    def define
      desc "Verify that rcov coverage is at least #{threshold}%"
      task @name do
        total_coverage = 0
        File.open(index_html).each_line do |line|
          if line =~ /<tt class='coverage_total'>\s*(\d+\.\d+)%\s*<\/tt>/
            total_coverage = $1.to_f
            break
          end
        end
        output_coverage(total_coverage)
      end
    end

    def output_coverage(total_coverage)
      puts "Coverage: #{total_coverage}% (threshold: #{threshold}%)".green if verbose && total_coverage >= threshold
      raise "Coverage must be at least #{threshold}% but was #{total_coverage}%".red if total_coverage < threshold
      raise "Coverage has increased above the threshold of #{threshold}% to #{total_coverage}%. You should update your threshold value.".red if (total_coverage > threshold) and require_exact_threshold
    end
  end
end
