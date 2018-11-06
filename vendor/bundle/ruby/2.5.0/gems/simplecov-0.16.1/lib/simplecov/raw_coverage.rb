# frozen_string_literal: true

module SimpleCov
  module RawCoverage
  module_function

    # Merges multiple Coverage.result hashes
    def merge_results(*results)
      results.reduce({}) do |result, merged|
        merge_resultsets(result, merged)
      end
    end

    # Merges two Coverage.result hashes
    def merge_resultsets(result1, result2)
      (result1.keys | result2.keys).each_with_object({}) do |filename, merged|
        file1 = result1[filename]
        file2 = result2[filename]
        merged[filename] = merge_file_coverage(file1, file2)
      end
    end

    def merge_file_coverage(file1, file2)
      return (file1 || file2).dup unless file1 && file2

      file1.map.with_index do |count1, index|
        count2 = file2[index]
        merge_line_coverage(count1, count2)
      end
    end

    def merge_line_coverage(count1, count2)
      sum = count1.to_i + count2.to_i
      if sum.zero? && (count1.nil? || count2.nil?)
        nil
      else
        sum
      end
    end
  end
end
