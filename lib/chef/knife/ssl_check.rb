require 'chef/knife'
require 'chef/config'

class Chef
  class Knife
    class SslCheck < Chef::Knife

      deps do
        require 'pp'
        require 'socket'
        require 'uri'
        require 'openssl'
      end

      def initialize(*args)
        @host = nil
        @verify_peer_socket = nil
        super
      end

      def host
        @host ||= begin
          url = Chef::Config.chef_server_url
          URI.parse(url).host
        end
      end

      def verify_peer_socket
        @verify_peer_socket ||= begin
          verify_peer_context = OpenSSL::SSL::SSLContext.new
          verify_peer_context.verify_mode = OpenSSL::SSL::VERIFY_PEER

          tcp_connection = TCPSocket.new(host, 443)
          OpenSSL::SSL::SSLSocket.new(tcp_connection, verify_peer_context)
        end
      end

      def noverify_socket
        @noverify_socket ||= begin
          tcp_connection = TCPSocket.new(host, 443)
          OpenSSL::SSL::SSLSocket.new(tcp_connection)
        end
      end

      def verify_cert
        verify_peer_socket.connect
      rescue OpenSSL::SSL::SSLError => e
        puts "ERROR: The SSL certificate of #{host} could not be verified"
        puts "ERROR: #{e.message}"
        debug_invalid_cert
        false
      end

      def verify_cert_host
        verify_peer_socket.post_connection_check(host)
      rescue OpenSSL::SSL::SSLError => e
        puts "ERROR: The SSL cert is trusted but is not valid for host #{host}"
        puts e.to_s
        debug_invalid_host
        false
      end

      def debug_invalid_cert
        noverify_socket.connect
        issuer_info = noverify_socket.peer_cert.issuer
        ui.msg("Certificate issuer data: #{issuer_info}")
      end

      def debug_invalid_host
        noverify_socket.connect
        subject = noverify_socket.peer_cert.subject
        cn_field_tuple = subject.to_a.find {|field| field[0] == "CN" }
        cn = cn_field_tuple[1]

        ui.msg("The given certificate is issued for host #{cn}")
      end

      def run
        if verify_cert && verify_cert_host
          ui.msg "certs are valid"
        else
          exit 1
        end
      end

    end
  end
end




