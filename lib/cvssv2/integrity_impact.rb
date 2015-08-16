module Cvssv2
  class IntegrityImpact
    def self.score(i)
      case i
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
