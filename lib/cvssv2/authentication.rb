module Cvssv2
  class Authentication
    def self.score(au)
      case au
      when 'M'
        0.45
      when 'S'
        0.56
      when 'N'
        0.704
      else
        0
      end
    end
  end
end
