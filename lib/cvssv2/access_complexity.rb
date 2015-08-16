module Cvssv2
  class AccessComplexity
    def self.score(ac)
      case ac
      when 'H'
        0.35
      when 'M'
        0.61
      when 'L'
        0.71
      else
        0
      end
    end
  end
end
