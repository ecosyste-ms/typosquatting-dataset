# frozen_string_literal: true

require 'csv'
require 'test/unit'
require 'uri'

class DatasetTest < Test::Unit::TestCase
  ROOT = File.expand_path('..', __dir__)
  HEADERS = %w[malicious_package target_package ecosystem registry classification source].freeze
  CLASSIFICATIONS = %w[
    omission repetition replacement transposition addition homoglyph vowel_swap
    delimiter word_order plural misspelling numeral bitflip adjacent_insertion
    double_hit combosquatting other
  ].freeze
  REGISTRIES = {
    'pypi' => 'https://pypi.org', 'npm' => 'https://npmjs.com',
    'crates.io' => 'https://crates.io', 'go' => 'https://pkg.go.dev',
    'github_actions' => 'https://github.com', 'rubygems' => 'https://rubygems.org'
  }.freeze
  ECOSYSTEM_NAMES = {
    'pypi' => 'PyPI', 'npm' => 'npm', 'crates.io' => 'crates.io',
    'go' => 'Go', 'github_actions' => 'GitHub Actions', 'rubygems' => 'RubyGems'
  }.freeze

  def setup
    @data = CSV.read(File.join(ROOT, 'typosquats.csv'), headers: true)
  end

  def test_csv_structure_and_metadata
    assert_equal HEADERS, @data.headers
    assert_not_empty @data
    @data.each do |row|
      assert_equal HEADERS.length, row.fields.length, row.inspect
      row.fields.each do |value|
        assert_not_nil value, row.inspect
        assert_not_empty value
        assert_equal value.strip, value
      end
      assert_include REGISTRIES, row['ecosystem']
      assert_equal REGISTRIES.fetch(row['ecosystem']), row['registry']
      assert_include CLASSIFICATIONS, row['classification']
      next unless row['source'].start_with?('https://')

      uri = URI.parse(row['source'])
      assert_not_nil uri.host
      assert_not_empty uri.path
    end
  end

  def test_unique_pairs
    keys = @data.map { |row| row.values_at('ecosystem', 'malicious_package', 'target_package') }
    assert_equal keys.uniq, keys
    @data.each { |row| assert_not_equal row['target_package'], row['malicious_package'] }
  end

  def test_simple_transformation_labels
    @data.each do |row|
      target = row['target_package'].downcase
      candidate = row['malicious_package'].downcase
      message = "#{target} -> #{candidate}: #{row['classification']}"
      case row['classification']
      when 'omission'
        assert target.length == candidate.length + 1, message
        assert target.length.times.any? { |i| target[0...i] + target[i + 1..] == candidate }, message
      when 'repetition'
        assert target.length.times.any? { |i| target[0..i] + target[i..] == candidate }, message
      when 'transposition'
        assert (0...target.length - 1).any? { |i|
          target[0...i] + target[i + 1] + target[i] + target[i + 2..] == candidate
        }, message
      when 'replacement', 'vowel_swap', 'bitflip'
        assert_equal target.length, candidate.length, message
        changed = target.length.times.select { |i| target[i] != candidate[i] }
        assert_equal 1, changed.length, message
        i = changed.first
        if row['classification'] == 'vowel_swap'
          assert_match(/\A[aeiou]{2}\z/, target[i] + candidate[i], message)
        elsif row['classification'] == 'bitflip'
          bits = target[i].ord ^ candidate[i].ord
          assert_equal 0, bits & (bits - 1), message
        end
      when 'addition'
        assert candidate.start_with?(target) || candidate.end_with?(target), message
      when 'delimiter'
        assert_equal target.delete('-_.'), candidate.delete('-_.'), message
      end
    end
  end

  def test_readme_summary_matches_csv
    readme = File.read(File.join(ROOT, 'README.md'))
    assert_include readme, "contains #{@data.size} name pairs"
    { 'ecosystem' => 'ecosystem', 'classification' => 'classification' }.each do |field, label|
      line = readme.lines.find { |text| text.start_with?("**By #{label}:**") }
      assert_not_nil line
      actual = line.scan(/([^,:]+) \((\d+)\)/).to_h.transform_values(&:to_i)
      expected = @data.group_by { |row| row[field] }.transform_values(&:size)
      expected = expected.transform_keys { |key| ECOSYSTEM_NAMES.fetch(key) } if field == 'ecosystem'
      actual = actual.transform_keys { |key| key.sub(/\A\*\*\s*/, '').strip }
      assert_equal expected, actual
    end
  end
end
