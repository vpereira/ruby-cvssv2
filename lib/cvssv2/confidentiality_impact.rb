module Cvssv2
  class ConfidentialityImpact
    def self.score(c)
      case c
      when 'P'
        0.275
      when 'C'
        0.660
      else # 'N' included
        0
      end
    end
  end
end
