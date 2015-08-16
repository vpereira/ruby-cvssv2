require "cvssv2/version"

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

  class Cvssv2
    attr_accessor :vector
    attr_reader :av,:ac,:au,:c,:i,:a,:e,:rl,:rc,:cdp,:td,:cr,:ir,:ar

    VECTOR_REGEXP = /\(AV:([LAN])\/AC:([HML])\/Au:([NSM])\/C:([NPC])\/I:([NPC])\/A:([NPC])(?:\/E:(ND|U|POC|F|H)\/RL:(ND|OF|TF|W|U)\/RC:(ND|UC|UR|C)(?:\/CDP:(N|L|LM|MH|H|ND)\/TD:(N|L|M|H|ND)\/CR:(L|M|H|ND)\/IR:(L|M|H|ND)\/AR:(L|M|H|ND))?)?\)/

    def initialize(v=nil)
      @vector = v
      parse if valid?
    end

    def valid?
      !!(@vector =~ VECTOR_REGEXP)
    end

    def parse
      @av,@ac,@au,@c,@i,@a,@e,@rl,@rc, \
      @cdp,@td,@cr,@ir,@ar = @vector.scan(VECTOR_REGEXP).flatten
    end

    def access_complexity
      AccessComplexity.score(@ac)
    end

    def authentication
      Authentication.score(@au)
    end

    def confidentiality
      AccessVector.score(@av)
    end

    def confidentiality_impact
      ConfidentialityImpact.score(@c)
    end

    def integrity_impact
      IntegrityImpact.score(@i)
    end

    def availability_impact
      AvailabilityImpact.score(@a)
    end

    def impact
      sprintf("%.2f",10.41 * (1.0 - (1.0 - confidentiality_impact) *
        (1.0 - integrity_impact) * (1.0- availability_impact))).to_f
    end

    def exploitability
      sprintf("%.2f",20 * access_complexity * authentication *
        confidentiality).to_f
    end

    def base_score

    end

  end
end
