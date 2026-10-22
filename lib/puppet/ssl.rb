# frozen_string_literal: true

# Just to make the constants work out.
require_relative '../puppet'
require_relative 'ssl/openssl_loader'

# Responsible for bootstrapping an agent's certificate and private key, generating
# SSLContexts for use in making HTTPS connections, and handling CSR attributes and
# certificate extensions.
#
# @see Puppet::SSL::SSLProvider
# @api private
module Puppet::SSL
  CA_NAME = "ca"

  def self.mldsa44_key?(key)
    # PKey#oid does not support ML-DSA in Ruby OpenSSL 4.0.2.
    key.is_a?(OpenSSL::PKey::PKey) &&
      OpenSSL::ASN1.decode(key.public_to_der).value[0].value[0].oid == '2.16.840.1.101.3.4.3.17'
  end

  require_relative 'ssl/oids'
  require_relative 'ssl/error'
  require_relative 'ssl/ssl_context'
  require_relative 'ssl/verifier'
  require_relative 'ssl/ssl_provider'
  require_relative 'ssl/state_machine'
  require_relative 'ssl/certificate'
  require_relative 'ssl/certificate_request'
  require_relative 'ssl/certificate_request_attributes'
end
