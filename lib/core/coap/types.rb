module CoRE
  module CoAP
    module Types
      # Arrays that describe a specific option type:
      # [default value, length range, repeatable?, decoder, encoder]

      # We only care about presence or absence, always empty.
      def presence_once
        [false, (0..0), false, ->(a) { true }, ->(v) { v ? [''] : []}]
      end

      # Token-style, goedelized in o256.
      def o256_once(min, max, default = nil)
        [default, (min..max), false,
         ->(a) { CoAP.o256_decode(a[0]) },
         ->(v) { v == default ? [] : [CoAP.o256_encode(v)] }
        ]
      end

      # Unused, for now.
      def o256_many(min, max)
        [nil, (min..max), true,
         ->(a) { a.map{ |x| CoAP.o256_decode(x)} },
         ->(v) { Array(v).map{ |x| CoAP.o256_encode(x)} }
        ]
      end

      # vlb as in core-coap Annex A
      def uint_once(min, max, default = nil)
        [default, (min..max), false,
         ->(a) { CoAP.vlb_decode(a[0]) },
         ->(v) { v == default ? [] : [CoAP.vlb_encode(v)] }
        ]
      end

      # this version will map strings accoring the mapper.
      def uint_once_mapped(min, max, default = nil, &mapper)
        [default, (min..max), false,
         ->(a) { CoAP.vlb_decode(a[0]) },
         ->(v) { v == default ? [] :
                   [
                     (if v.is_a? String
                       v = mapper.call(v)
                     end
                     CoAP.vlb_encode(v))
                   ]
         }
        ]
      end

      def uint_many(min, max)
        [nil, (min..max), true,
         ->(a) { a.map{ |x| CoAP.vlb_decode(x)} },
         ->(v) { Array(v).map{ |x| CoAP.vlb_encode(x)} }
        ]
      end

      # Any other opaque byte sequence (once).
      def opaq_once(min, max, default = nil)
        [default, (min..max), false,
         ->(a) { a[0] },
         ->(v) { v == default ? [] : Array(v) }
        ]
      end

      # Any other opaque byte sequence (many).
      def opaq_many(min, max)
        [nil, (min..max), true, ->(a) { a }, ->(v) { Array(v) }]
      end

      # Same, but interpreted as UTF-8
      def str_once(min, max, default = nil)
        [default, (min..max), false,
          ->(a) { a[0] },
          ->(v) { v == default ? [] : Array(v) }
        ]
      end

      def str_many(min, max)
        [nil, (min..max), true, ->(a) { a }, ->(v) { Array(v) }]
      end
    end
  end
end
