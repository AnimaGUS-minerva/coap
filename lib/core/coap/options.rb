module CoRE
  module CoAP
    module Options
      extend Types

      CONTENT_TYPES = {
        "text/plain; charset=utf-8" => 0,    # [RFC2046][RFC3676][RFC5147]
        "application/cose; cose-type=\"cose-encrypt0\"" => 16, # [RFC8152]
        "application/cose; cose-type=\"cose-mac0\""     => 17, # [RFC8152]
        "application/cose; cose-type=""cose-sign1\""    => 18, # [RFC8152]
        "application/link-format"                       => 40, # [RFC6690]
        "application/xml"                               => 41, # [RFC3023]
        "application/octet-stream"                      => 42, # [RFC2045][RFC2046]

        #"[""Efficient XML Interchange (EXI) Format 1.0 (Second Edition)"", February 2014]"
        "application/exi"                               => 47,
        "application/json"                              => 50, # [RFC4627]
        "application/json-patch+json"                   => 51, # [RFC6902]
        "application/merge-patch+json"                  => 52, # [RFC7396]
        "application/cbor"                              => 60, # [RFC7049]
        "application/cwt"           => 61, # [RFC-ietf-ace-cbor-web-token-15]
        "application/cose; cose-type=\"cose-encrypt\""  => 96, # [RFC8152]
        "application/cose; cose-type=\"cose-mac\""      => 97, # [RFC8152]
        "application/cose; cose-type=\"cose-sign\""     => 98, # [RFC8152]
        "application/cose-key"                         => 101, # [RFC8152]
        "application/cose-key-set"                     => 102, # [RFC8152]
        "application/coap-group+json"    => 256,  # [RFC7390]
        "application/vnd.ocf+cbor"       => 10000,# [Michael_Koster]
        "application/vnd.oma.lwm2m+tlv"  => 11542,# [OMA-TS-LightweightM2M-V1_0]
        "application/vnd.oma.lwm2m+json" => 11543,# [OMA-TS-LightweightM2M-V1_0]
      }

      def self.content_type_mapper(ct)
        CONTENT_TYPES[ct]
      end

      TOKEN_ON = 19

      # 14 => :user, default, length range, replicable?, decoder, encoder
      OPTIONS = { # name      minlength, maxlength, [default]    defined where:
         1 => [:if_match,       *o256_many(0, 8)],     # RFC7252
         3 => [:uri_host,       *str_once(1, 255)],    # RFC7252
         4 => [:etag,           *o256_many(1, 8)],     # RFC7252 !! once in rp
         5 => [:if_none_match,  *presence_once],       # RFC7252
         6 => [:observe,        *uint_once(0, 3)],     # core-observe-07
         7 => [:uri_port,       *uint_once(0, 2)],     # RFC7252
         8 => [:location_path,  *str_many(0, 255)],    # RFC7252
        11 => [:uri_path,       *str_many(0, 255)],    # RFC7252
        12 => [:content_format, *uint_once_mapped(0, 2, nil) { |x| content_type_mapper(x) }],     # RFC7252
        14 => [:max_age,        *uint_once(0, 4, 60)], # RFC7252
        15 => [:uri_query,      *str_many(0, 255)],    # RFC7252
        17 => [:accept,         *uint_once(0, 2)],     # RFC7252
        TOKEN_ON => [:token,    *o256_once(1, 8, 0)],  # RFC7252 -> opaq_once(1, 8, EMPTY)
        20 => [:location_query, *str_many(0, 255)],    # RFC7252
        23 => [:block2,         *uint_once(0, 3)],     # RFC7959
        27 => [:block1,         *uint_once(0, 3)],     # RFC7959
        28 => [:size2,          *uint_once(0, 4)],     # RFC7959
        35 => [:proxy_uri,      *str_once(1, 1034)],   # RFC7252
        39 => [:proxy_scheme,   *str_once(1, 255)],    # RFC7252
        60 => [:size1,          *uint_once(0, 4)],     # RFC7959
      }

      # :user => 14, :user, def, range, rep, deco, enco
      OPTIONS_I =
        Hash[OPTIONS.map { |k, v| [v[0], [k, *v]] }]

      DEFAULTING_OPTIONS =
        Hash[
          OPTIONS
            .map { |k, v| [v[0].freeze, v[1].freeze] }
            .select { |k, v| v }
        ].freeze
    end
  end
end
