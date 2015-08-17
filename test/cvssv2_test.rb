require 'test_helper'

# base score metrics, with a valid vector
class Cvssv2Test < Minitest::Test
  def setup
    @cvssv2 = Cvssv2::Cvssv2.new "(AV:N/AC:M/Au:N/C:P/I:P/A:P)"
  end

  def test_it_does_something_useful
    refute_nil @cvssv2
  end

  def test_that_it_has_a_version_number
    refute_nil ::Cvssv2::VERSION
  end

  def test_vector_should_be_valid
    refute @cvssv2.valid? == false
  end

  def test_parsing_results
    assert_equal @cvssv2.av,"N"
    assert_equal @cvssv2.ac,"M"
    assert_equal @cvssv2.au,"N"
    assert_equal @cvssv2.c,"P"
  end
end

# invalid vector
class Cvssv2Test2 < Minitest::Test
  def setup
    @cvssv2 = Cvssv2::Cvssv2.new "(XX:Y/AAAA:H/Au:N/C:X/X:P/A:P)"
  end

  def test_vector_should_be_valid
    refute @cvssv2.valid? == true
  end

  def test_av
    assert_nil @cvssv2.av
  end
end

# full vector should be test
class Cvss2Test3 < MiniTest::Test
  def setup
    @cvssv2 = Cvssv2::Cvssv2.new "(AV:N/AC:M/Au:N/C:P/I:P/A:P/E:POC/RL:TF/RC:UR/CDP:L/TD:M/CR:M/IR:ND/AR:ND)"
  end

  def test_vector_should_be_valid
    refute @cvssv2.valid? == false
  end

  def test_vector_should_not_be_nil
    refute_nil @cvssv2.parse
  end

  def test_impact
    assert_equal 6.44,@cvssv2.impact
  end

  def test_exploitability
    assert_in_delta 8.60,@cvssv2.exploitability,0.05
  end

  def test_base_score
    assert_in_delta 6.80,@cvssv2.base_score,0.05
  end

end

class ScoreTest < MiniTest::Test
  def setup
    @cvssv2 = Cvssv2::Cvssv2.new "(AV:N/AC:M/Au:N/C:P/I:P/A:P/E:POC/RL:TF/RC:UR/CDP:L/TD:M/CR:M/IR:ND/AR:ND)"
  end

  def test_access_vector
    assert_equal Cvssv2::AccessVector.score(@cvssv2.av),1
    refute_equal Cvssv2::AccessVector.score(@cvssv2.av),0.33
  end

  def test_access_complexity
    assert_equal Cvssv2::AccessComplexity.score(@cvssv2.ac), 0.61
    refute_equal Cvssv2::AccessComplexity.score(@cvssv2.ac), 0.35
  end

  def test_authentication
    assert_equal Cvssv2::Authentication.score(@cvssv2.au), 0.704
    refute_equal Cvssv2::Authentication.score(@cvssv2.au), 0.35
  end

  def test_confidentiality_impact
    assert_equal Cvssv2::ConfidentialityImpact.score(@cvssv2.c), 0.275
    refute_equal Cvssv2::ConfidentialityImpact.score(@cvssv2.c), 0
  end

  def test_integrity_impact
    assert_equal Cvssv2::IntegrityImpact.score(@cvssv2.c), 0.275
    refute_equal Cvssv2::IntegrityImpact.score(@cvssv2.c), 0
  end

  def test_availability_impact
    assert_equal Cvssv2::AvailabilityImpact.score(@cvssv2.c), 0.275
    refute_equal Cvssv2::AvailabilityImpact.score(@cvssv2.c), 0
  end
end
