# encoding: utf-8

module CoRE
  module CoAP
    # CoAP client library
    class Client

      class NotDTLSSocket < Exception
      end

      attr_accessor :max_payload, :host, :port, :scheme, :logger, :io, :dtls
      attr_accessor :client_cert, :client_key

      # @param  options   Valid options are (all optional): max_payload
      #                   (maximum payload size, default 256), max_retransmit
      #                   (maximum retransmission count, default 4),
      #                   recv_timeout (timeout for ACK responses, default: 2),
      #                   scheme (coap: or coaps:)
      #                   host (destination host), post (destination port,
      #                   default 5683).
      def initialize(options = {})
        @max_payload = options[:max_payload] || 256

        @host = options[:host]
        @scheme=(options[:scheme] || :coap).to_sym
        defport = CoAP::PORT
        case @scheme
        when :coap
          nil
        when :coaps
          defport = CoAP::DTLS_PORT
        end

        @port = options[:port] || defport

        @options = options

        @logger = CoAP.logger
      end

      # Enable DTLS socket.
      def use_codtls
        require 'CoDTLS'
        @options[:socket] = CoDTLS::SecureSocket
        self
      end

      # GET
      #
      # @param  path      Path
      # @param  host      Destination host
      # @param  port      Destination port
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def get(*args)
        client(:get, *args)
      end

      # GET by URI
      #
      # @param  uri       URI
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def get_by_uri(uri, *args)
        get(*decode_uri(uri), *args)
      end

      # POST
      #
      # @param  host      Destination host
      # @param  port      Destination port
      # @param  path      Path
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def post(*args)
        client(:post, *args)
      end

      # POST by URI
      #
      # @param  uri       URI
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def post_by_uri(uri, *args)
        post(*decode_uri(uri), *args)
      end

      # PUT
      #
      # @param  host      Destination host
      # @param  port      Destination port
      # @param  path      Path
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def put(*args)
        client(:put, *args)
      end

      # PUT by URI
      #
      # @param  uri       URI
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def put_by_uri(uri, *args)
        put(*decode_uri(uri), *args)
      end

      # DELETE
      #
      # @param  host      Destination host
      # @param  port      Destination port
      # @param  path      Path
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def delete(*args)
        client(:delete, *args)
      end

      # DELETE by URI
      #
      # @param  uri       URI
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def delete_by_uri(uri, *args)
        delete(*decode_uri(uri), *args)
      end

      # OBSERVE
      #
      # @param  host      Destination host
      # @param  port      Destination port
      # @param  path      Path
      # @param  callback  Method to call with the observe data. Must provide
      #                   arguments payload and socket.
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def observe(path, host, port, callback, payload = nil, options = {})
        options[:observe] = 0
        client(:get, path, host, port, payload, options, callback)
      end

      # OBSERVE by URI
      #
      # @param  uri       URI
      # @param  callback  Method to call with the observe data. Must provide
      #                   arguments payload and socket.
      # @param  payload   Payload
      # @param  options   Options
      #
      # @return CoAP::Message
      def observe_by_uri(uri, *args)
        observe(*decode_uri(uri), *args)
      end

      def peer_cert
        raise NotDTLSSocket unless @scheme == :coaps
        @dtls.peer_cert
      end

      def client_cert=(x)
        raise NotDTLSSocket unless @scheme == :coaps

        @client_cert = x
      end

      def client_key=(x)
        raise NotDTLSSocket unless @scheme == :coaps

        @client_key = x
      end

      private

      def make_io_channel
        info   = Addrinfo.udp(host, port)
        usock  = UDPSocket::new(info.afamily)
        usock.connect(info.ip_address, info.ip_port)
        sock   = Celluloid::IO::UDPSocket.new(usock)

        if @scheme == :coaps
          sslctx = OpenSSL::SSL::DTLSContext.new
          #sslctx.min_version = OpenSSL::SSL::TLS1_1_VERSION

          # need a way to get at this setting too.
          sslctx.verify_mode = OpenSSL::SSL::VERIFY_NONE

          if @client_cert
            sslctx.cert = @client_cert
            sslctx.key  = @client_key
          end

          # XXX consider if DTLS handshake should be done here?
          @dtls              = OpenSSL::SSL::DTLSSocket.new(usock, sslctx)
          @options[:socket]  = @dtls
          @options[:iosocket] = sock
        else
          @options[:socket] = sock
        end
        @options[:socket]
      end

      def io
        @io ||= make_io_channel
      end

      def client_send_blocks(method: :client,
                             message:,
                             host: , port:,
                             path: '',
                             socket:,
                             blocks: ,
                             coapoptions: {})

        message.options[:mid] = message.mid

        coapoptions.delete(:block1)
        message.options.merge!(coapoptions)

        blocks.each { |block|
          # If more than 1 chunk, we need to use block1.

          # More chunks?
          if blocks.size > block.num + 1
            block.more = true
            message.options.delete(:block2)
          else
            block.more = false
          end

          # Set block1 message option.
          message.options[:block1] = block.encode

          # Set final payload.
          message.payload = block.data

          # Wait for answer and retry sending message if timeout reached.
          @transmission, recv_parsed = Transmission.request(message, host, port, coapoptions)
          log_message(:received_message, recv_parsed)
        }

        return @transmission, recv_parsed
      end

      def client(method, path, host = nil, port = nil, payload = nil, coapoptions = {}, observe_callback = nil)

        # Set host and port only one time on multiple requests
        host.nil? ? (host = @host unless @host.nil?) : @host = host
        port.nil? ? (port = @port unless @port.nil?) : @port = port

        query = nil
        case path
        when String
          path, query = path.split('?')
        when URI::Generic
          uri   = path
          path  = path.path
          query = nil
        end

        validate_arguments!(host, port, path, payload)

        szx = 2 ** CoAP.number_of_bits_up_to(@max_payload)

        # Initialize block2 with payload size.
        block2 = Block.new(0, false, szx)

        # Initialize chunks if payload size > max_payload.
        if !payload.nil?
          chunks = Block.chunkify(payload, @max_payload)
        end

        # Create CoAP message struct.
        message = initialize_message(method, scheme, path, query, payload)
        message.mid = coapoptions.delete(:mid) if coapoptions[:mid]

        # Set message type to non if chosen in global or local options.
        if coapoptions.delete(:tt) == :non || @options.delete(:tt) == :non
          message.tt = :non
        end

        # Preserve user options.
        message.options[:block2]  = coapoptions[:block2]  unless coapoptions[:block2] == nil
        message.options[:observe] = coapoptions[:observe] unless coapoptions[:observe] == nil

        log_message(:sending_message, message)
        log_message(:target, [host,port])

        # make sure that the @options[:socket] is filled in
        coapoptions[:socket] = io

        if chunks
          # something to send
          @transmission,recv_parsed = client_send_blocks(method: method, message: message,
                                                         host: host,
                                                         port: port,
                                                         path: path, socket: io,
                                                         blocks: chunks,
                                                         coapoptions: coapoptions)
        else
          # nothing to send, just a GET
          @transmission, recv_parsed = Transmission.request(message, host, port, coapoptions)
          log_message(:received_message, recv_parsed)
        end

        # Test for more block2 payload.
        block2 = Block.new(recv_parsed.options[:block2]).decode

        if block2.more
          block2.num += 1

          coapoptions.delete(:block1) # end block1
          coapoptions[:block2] = block2.encode

          # more recursion to get block2 back.
          local_recv_parsed = client(method, path, host, port, nil, coapoptions)

          unless local_recv_parsed.nil?
            recv_parsed.payload << local_recv_parsed.payload
          end
        end

        # Do we need to observe?
        if recv_parsed.options[:observe]
          CoAP::Observer.new.observe(recv_parsed, observe_callback, @transmission)
        end

        recv_parsed
      end

      private

      # Decode CoAP URIs.
      def decode_uri(uri)
        uri = CoAP.scheme_and_authority_decode(uri.to_s)

        @logger.debug 'URI decoded: ' + uri.inspect
        fail ArgumentError, 'Invalid URI' if uri.nil?

        uri
      end

      def initialize_message(method, uri_scheme, path, query = nil, payload = nil)
        mid = SecureRandom.random_number(0xffff)

        scheme = uri_scheme
        options = {
          uri_path: CoAP.path_decode(path),
        }

        unless @options[:token] == false
          options[:token] = SecureRandom.random_number(0xffffffff)
        end

        unless query.nil?
          options[:uri_query] = CoAP.query_decode(query)
        end
        Message.new({ :options => options,
                      :payload => payload,
                      :scheme  => scheme,
                      :tt      => :con,
                      :mcode   => method,
                      :mid     => mid})
      end

      # Log message to debug log.
      def log_message(text, message)
        @logger.debug '### ' + text.to_s.upcase.gsub('_', ' ')
        @logger.debug message.inspect
        @logger.debug message.to_s.hexdump if $DEBUG
      end

      # Raise ArgumentError exceptions on wrong client method arguments.
      def validate_arguments!(host, port, path, payload)
        if host.nil? || host.empty?
          fail ArgumentError, 'Argument «host» missing.'
        end

        if port.nil? || !port.is_a?(Integer)
          fail ArgumentError, 'Argument «port» missing or not an Integer.'
        end

        if path.nil? || path.empty?
          fail ArgumentError, 'Argument «path» missing.'
        end

        if !payload.nil? && (payload.empty? || !payload.is_a?(String))
          fail ArgumentError, 'Argument «payload» must be a non-emtpy String'
        end
      end
    end
  end
end
