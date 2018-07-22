# coapmessage.rb
# Copyright (C) 2010..2013 Carsten Bormann <cabo@tzi.org>

module CoRE
  module CoAP
    extend Utility

    include Coding
    include Options

    EMPTY = empty_buffer.freeze

    TTYPES = [:con, :non, :ack, :rst]
    TTYPES_I = invert_into_hash(TTYPES)

    METHODS = [nil, :get, :post, :put, :delete]
    METHODS_I = invert_into_hash(METHODS)

    PORT = 5683
    DTLS_PORT=5684

    # Shortcut: CoRE::CoAP::parse == CoRE::CoAP::Message.parse
    def self.parse(*args)
      Message.parse(*args)
    end
  end
end
