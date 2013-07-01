class EmitableExample
  def initialize(example)
    @example = example
  end

  def metric
    'bosh.ci.bat.test_example_duration3'
  end

  def value
    run_time
  end

  def options
    { tags: %W[infrastructure:test example:#{description}] }
  end

  def to_a
    [metric, value, options]
  end


  private
  attr_reader :example

  def run_time
    example.metadata.fetch(:execution_result).fetch(:run_time)
  end

  def description
    example.metadata.fetch(:description).downcase.tr(',/()', '').tr(' :', '-').squeeze('-')
  end
end