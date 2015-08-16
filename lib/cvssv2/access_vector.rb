module Cvssv2
  class AccessVector
    def self.score(av)
      case av
      when 'L'
        0.395
      when 'A'
        0.646
      when 'N'
        1
      else
        0
      end
    end
  end
end
