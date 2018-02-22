module CoRE
  module CoAP
    # Socket abstraction.
    class Transmission
      DEFAULT_RECV_TIMEOUT = 2

      attr_accessor :max_retransmit, :recv_timeout
      attr_reader :address_family, :socket

      def initialize(options = {})
        @max_retransmit   = options[:max_retransmit] || 4
        @recv_timeout     = options[:recv_timeout]   || DEFAULT_RECV_TIMEOUT
        @socket           = options[:socket]
        @force_ipv6       = !!options[:force_ipv6]

        @retransmit       = if options[:retransmit].nil?
                              true
                            else
                              !!options[:retransmit]
                            end

        if @socket
          @socket_class   = @socket.class
          @address_family = @socket.addr.first
        else
          @socket_class   = options[:socket_class]   || Celluloid::IO::UDPSocket
          @address_family = options[:address_family] || Socket::AF_INET6
          @socket         = @socket_class.new(@address_family)
        end

        # http://lists.apple.com/archives/darwin-kernel/2014/Mar/msg00012.html
        if OS.osx? && ipv6?
          ifname  = Socket.if_up?('en1') ? 'en1' : 'en0'
          ifindex = Socket.if_nametoindex(ifname)

          s = @socket.to_io rescue @socket
          s.setsockopt(:IPPROTO_IPV6, :IPV6_MULTICAST_IF, [ifindex].pack('i_'))
        end

        @socket
      end

      def ipv6?
        @address_family == Socket::AF_INET6
      end

      # Receive from socket and return parsed CoAP message. (ACK is sent on CON
      # messages.)
      def receive(options = {})
        retry_count = options[:retry_count] || 0
        timeout = (options[:timeout] || @recv_timeout) ** (retry_count + 1)

        mid   = options[:mid]
        flags = mid.nil? ? 0 : Socket::MSG_PEEK

        data = Timeout.timeout(timeout) do
          #STDERR.puts "calling recvfrom on #{@socket}"
          @socket.recvfrom(1152, flags)
        end

        answer = CoAP.parse(data[0].force_encoding('BINARY'))

        if mid == answer.mid
          Timeout.timeout(1) { @socket.recvfrom(1152) }
        end

        if answer.tt == :con
          message = Message.new(:ack, 0, answer.mid, nil,
            {token: answer.options[:token]})

          send(message, data[1][3])
        end

        answer
      end

      # Send +message+ (retransmit if necessary) and wait for answer. Returns
      # answer.
      def request(message, host, port = CoAP::PORT)
        retry_count = 0
        retransmit = @retransmit && message.tt == :con

        STDERR.puts "TRANSMITTING: #{host} #{port}"
        #byebug
        sendmesg(message, host, port)

        begin
          response = receive(retry_count: retry_count, mid: message.mid)
        rescue Timeout::Error
          raise unless retransmit

          retry_count += 1

          if retry_count > @max_retransmit
            raise "Maximum retransmission count of #{@max_retransmit} reached."
          end

          retry unless message.tt == :non
        end

        if seperate?(response)
          response = receive(timeout: 10, mid: message.mid)
        end

        response
      end

      # Send +message+.
      def sendmesg(message, host, port = CoAP::PORT)
        message = message.to_wire if message.respond_to?(:to_wire)

        # In MRI and Rubinius, the Socket::MSG_DONTWAIT option is 64.
        # It is not defined by JRuby.
        # TODO Is it really necessary?

        # XXX change to sendmsg()
        @socket.send(message, 64, host, port)
      end

      private

      # Check if answer is seperated.
      def seperate?(response)
        r = response
        r.tt == :ack && r.payload.empty? && r.mcode == [0, 0]
      end

      class << self
        # Return Transmission instance with socket matching address family.
        def from_host(host, options = {})
          if IPAddr.new(host).ipv6? 
            new(options)
          else
            new(options.merge(address_family: Socket::AF_INET))
          end
        # MRI throws IPAddr::InvalidAddressError, JRuby an ArgumentError
        rescue ArgumentError
          host = Resolver.address(host, options[:force_ipv6])
          retry
        end

        # Instanciate matching Transmission and send message.
        def send(*args)
          invoke(:send, *args)
        end

        # Instanciate matching Transmission and perform request.
        def request(*args)
          invoke(:request, *args)
        end

        private

        # Instanciate matching Transmission and invoke +method+ on instance.
        def invoke(method, *args)
          options = {}
          options = args.pop if args.last.is_a? Hash

          if options[:socket]
            transmission = Transmission.new(options)
          else
            transmission = from_host(args[1], options)
          end

          [transmission, transmission.__send__(method, *args)]
        end
      end
    end
  end
end
