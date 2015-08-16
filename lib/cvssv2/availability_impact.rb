module Cvssv2
    class AvailabilityImpact
      def self.score(a)
        case a
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
