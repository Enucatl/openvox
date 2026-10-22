# frozen_string_literal: true

# Run with the packaged Ruby/OpenSSL 3.5+: ruby -Ilib spec/integration/ssl/mldsa_self_check.rb
require 'puppet'
require 'puppet/application/ssl'
require 'tmpdir'
require 'fileutils'
require 'base64'

checks = 0
assert = lambda do |condition, message|
  raise message unless condition

  checks += 1
end
reject = lambda do |error, message = nil, &block|
  begin
    block.call
  rescue error => e
    raise "Expected error containing #{message.inspect}, got #{e.message.inspect}" if message && !e.message.include?(message)

    checks += 1
  else
    raise "Expected #{error}"
  end
end

# Decode the actual file bytes: PKey#private_to_der would apply OpenSSL's policy again.
persisted_der = lambda do |path|
  Base64.strict_decode64(File.read(path).lines.reject { |line| line.start_with?('-----') }.join.delete("\n"))
end
assert_seed = lambda do |der, label|
  pkcs8 = OpenSSL::ASN1.decode(der)
  assert.call(pkcs8.value[1].value[0].oid == '2.16.840.1.101.3.4.3.17', "#{label}: ML-DSA-44 OID")
  seed = OpenSSL::ASN1.decode(pkcs8.value[2].value)
  assert.call(seed.tag_class == :CONTEXT_SPECIFIC && seed.tag == 0 && seed.value.is_a?(String) && seed.value.bytesize == 32,
              "#{label}: private-key payload is implicit [0] containing exactly 32 seed bytes")
end
assert_signatures = lambda do |original, loaded, label|
  message = 'ML-DSA persistence round trip'
  assert.call(loaded.verify(nil, original.sign(nil, message), message), "#{label}: original signature verifies after load")
  assert.call(original.verify(nil, loaded.sign(nil, message), message), "#{label}: loaded key signature verifies with original")
end
assert.call(!ENV.key?('OPENSSL_CONF'), 'Run with OPENSSL_CONF unset')
assert.call(!ENV.fetch('RUBYOPT', '').include?('openvox-child-policy'), 'Run without the child policy helper')

puts "Ruby #{RUBY_VERSION}; Ruby OpenSSL #{OpenSSL::VERSION}; #{OpenSSL::OPENSSL_LIBRARY_VERSION}"
assert.call(Puppet[:key_type] == 'rsa', 'RSA must remain the default')
reject.call(Puppet::Settings::ValidationError) do
  Puppet[:key_type] = 'ML-DSA-65'
  Puppet[:key_type]
end
Puppet[:key_type] = 'rsa'

Dir.mktmpdir('openvox-mldsa') do |dir|
  Puppet.initialize_settings(['--confdir', dir, '--vardir', dir, '--ssldir', "#{dir}/ssl", '--certname', 'agent.test'])
  Puppet[:hostcert_renewal_interval] = 0
  FileUtils.mkdir_p([Puppet[:privatekeydir], Puppet[:certdir], Puppet[:requestdir]])
  cert_provider = Puppet::X509::CertProvider.new
  ssl_provider = Puppet::SSL::SSLProvider.new

  %w[rsa ec mldsa44].each do |algorithm|
    Puppet[:key_type] = algorithm
    Puppet[:keylength] = 2048
    FileUtils.rm_f(Puppet[:hostprivkey])
    machine = Puppet::SSL::StateMachine.new(cert_provider: cert_provider, ssl_provider: ssl_provider)
    context = Puppet::SSL::SSLContext.new(cacerts: [], crls: [])
    state = Puppet::SSL::StateMachine::NeedKey.new(machine, context).next_state
    key = state.private_key
    assert.call(state.is_a?(Puppet::SSL::StateMachine::NeedSubmitCSR), "#{algorithm}: CSR state")
    loaded = cert_provider.load_private_key(Puppet[:certname], required: true)
    assert.call(key.public_to_der == loaded.public_to_der, "#{algorithm}: persisted private key")
    assert.call((File.stat(Puppet[:hostprivkey]).mode & 0o777) == 0o640, "#{algorithm}: private key permissions")
    if algorithm == 'mldsa44'
      assert_seed.call(persisted_der.call(Puppet[:hostprivkey]), 'enrollment')
      assert_signatures.call(key, loaded, 'unencrypted')
      # An existing expanded key must be reused byte for byte, without migration.
      expanded_pem = key.private_to_pem
      expanded_info = OpenSSL::ASN1.decode(Base64.decode64(expanded_pem.lines.reject { |line| line.start_with?('-----') }.join))
      expanded_payload = OpenSSL::ASN1.decode(expanded_info.value[2].value)
      assert.call(expanded_payload.is_a?(OpenSSL::ASN1::Sequence) && expanded_payload.value.map { |part| part.value.bytesize } == [32, 2560],
                  'OpenSSL default without policy is seed plus expanded key')
      File.write(Puppet[:hostprivkey], expanded_pem)
    end
    existing_bytes = File.binread(Puppet[:hostprivkey])
    reused = Puppet::SSL::StateMachine::NeedKey.new(machine, context).next_state.private_key
    assert.call(key.public_to_der == reused.public_to_der, "#{algorithm}: existing key reused")

    assert.call(File.binread(Puppet[:hostprivkey]) == existing_bytes, "#{algorithm}: existing key file unchanged")

    csr = cert_provider.create_request(Puppet[:certname], loaded)
    assert.call(csr.verify(csr.public_key), "#{algorithm}: CSR signature")
    assert.call(csr.public_key.public_to_der == key.public_to_der, "#{algorithm}: CSR public key")
    ssl_provider.verify_request(csr, loaded)
    cert_provider.save_request(Puppet[:certname], csr)
    assert.call(OpenSSL::X509::Request.new(File.read(Puppet[:hostcsr])).verify(loaded), "#{algorithm}: saved CSR")

    cert_provider.save_private_key(Puppet[:certname], key, password: 'test-password')
    encrypted_key = cert_provider.load_private_key(Puppet[:certname], password: 'test-password', required: true)
    assert.call(encrypted_key.public_to_der == key.public_to_der, "#{algorithm}: encrypted private key")
    reject.call(OpenSSL::PKey::PKeyError) { cert_provider.load_private_key(Puppet[:certname], password: 'wrong-password') }
    if algorithm == 'mldsa44'
      encrypted = OpenSSL::ASN1.decode(persisted_der.call(Puppet[:hostprivkey]))
      assert.call(encrypted.value[0].value[0].oid == '1.2.840.113549.1.5.13', 'encrypted key: PBES2')
      parameters = encrypted.value[0].value[1].value
      kdf = parameters[0].value[1].value
      assert.call(parameters[0].value[0].oid == '1.2.840.113549.1.5.12', 'encrypted key: PBKDF2')
      assert.call(kdf[1].value.to_i == 2048, 'encrypted key: 2048 PBKDF2 iterations')
      assert.call(kdf.last.value[0].oid == '1.2.840.113549.2.9', 'encrypted key: HMAC-SHA256')
      encryption = parameters[1].value
      assert.call(encryption[0].oid == '2.16.840.1.101.3.4.1.2', 'encrypted key: AES128-CBC')
      assert.call((File.stat(Puppet[:hostprivkey]).mode & 0o777) == 0o640, 'encrypted key: permissions')
      cipher = OpenSSL::Cipher.new('aes-128-cbc')
      cipher.decrypt
      cipher.key = OpenSSL::PKCS5.pbkdf2_hmac('test-password', kdf[0].value, kdf[1].value.to_i, cipher.key_len, 'SHA256')
      cipher.iv = encryption[1].value
      assert_seed.call(cipher.update(encrypted.value[1].value) + cipher.final, 'encrypted save')
      assert_signatures.call(key, encrypted_key, 'encrypted')

      FileUtils.rm_f(Puppet[:hostprivkey])
      replacement = Puppet::SSL::StateMachine::NeedKey.new(machine, context).next_state.private_key
      assert.call(replacement.public_to_der != key.public_to_der, 'rotation: generates a replacement key')
      assert_seed.call(persisted_der.call(Puppet[:hostprivkey]), 'rotation')
      FileUtils.rm_f(Puppet[:hostprivkey])
      application = Puppet::Application::Ssl.allocate
      application.instance_variable_set(:@cert_provider, cert_provider)
      application.generate_request(Puppet[:certname])
      assert_seed.call(persisted_der.call(Puppet[:hostprivkey]), 'CLI generate_request')
    end

    cli_key = Puppet::Application::Ssl.allocate.send(:create_key, Puppet[:certname])
    assert.call(cli_key.public_to_der != key.public_to_der, "#{algorithm}: CLI generates a fresh key")
    assert.call(Puppet::SSL.mldsa44_key?(cli_key) == (algorithm == 'mldsa44'), "#{algorithm}: CLI key algorithm")

    next unless algorithm == 'mldsa44'

    assert.call(Puppet::SSL.mldsa44_key?(loaded), 'ML-DSA-44 public key OID')
    assert.call(csr.signature_algorithm == 'ML-DSA-44', 'ML-DSA-44 CSR signature algorithm')
    named_request = Puppet::SSL::CertificateRequest.new(Puppet[:certname])
    named_request.generate(key, dns_alt_names: 'alias.test', csr_attributes: { '1.2.3.4' => 'test' })
    assert.call(named_request.subject_alt_names == ['DNS:agent.test', 'DNS:alias.test'], 'ML-DSA SAN preservation')
    assert.call(named_request.custom_attributes == [{ 'oid' => '1.2.3.4', 'value' => 'test' }], 'ML-DSA CSR attribute preservation')

    root = OpenSSL::X509::Certificate.new
    root.version = 2
    root.serial = 1
    root.subject = OpenSSL::X509::Name.parse('/CN=ML-DSA test root')
    root.issuer = root.subject
    root.public_key = key
    root.not_before = Time.now - 60
    root.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = root
    factory.issuer_certificate = root
    root.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    root.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    root.sign(key, nil)
    leaf_key = cli_key
    leaf = OpenSSL::X509::Certificate.new
    leaf.version = 2
    leaf.serial = 2
    leaf.subject = csr.subject
    leaf.issuer = root.subject
    leaf.public_key = leaf_key
    leaf.not_before = root.not_before
    leaf.not_after = root.not_after
    leaf.sign(key, nil)
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = root.subject
    crl.last_update = Time.now - 60
    crl.next_update = Time.now + 3600
    crl.sign(key, nil)
    args = { cacerts: [root], crls: [crl], client_cert: leaf }
    verified = ssl_provider.create_context(**args, private_key: leaf_key)
    assert.call(verified.private_key == leaf_key, 'ML-DSA chain, CRL and matching private key accepted')
    reject.call(Puppet::SSL::SSLError) { ssl_provider.create_context(**args, private_key: key) }
    reject.call(Puppet::SSL::SSLError, 'Unsupported key') { ssl_provider.create_context(**args, private_key: OpenSSL::PKey.generate_key('ML-DSA-65')) }
    cert_provider.save_private_key(Puppet[:certname], leaf_key)
    before_renewal = File.binread(Puppet[:hostprivkey])
    renewal_route = Object.new
    renewal_route.define_singleton_method(:post_certificate_renewal) { |_context| [nil, leaf.to_pem] }
    renewal_session = Object.new
    renewal_session.define_singleton_method(:route_to) { |*_args, **_options| renewal_route }
    machine.define_singleton_method(:session) { renewal_session }
    renewed = Puppet::SSL::StateMachine::NeedRenewedCert.new(machine, verified, leaf_key).next_state
    assert.call(renewed.is_a?(Puppet::SSL::StateMachine::Done), 'renewal completes')
    assert.call(File.binread(Puppet[:hostprivkey]) == before_renewal, 'renewal preserves existing private-key bytes')
    assert.call(File.read(Puppet[:hostcert]) == leaf.to_pem, 'renewal saves the renewed certificate')
    rogue_root = root.dup
    rogue_root.public_key = leaf_key
    rogue_root.sign(leaf_key, nil)
    reject.call(Puppet::SSL::CertVerifyError) { ssl_provider.create_context(**args.merge(cacerts: [rogue_root]), private_key: leaf_key) }
    revoked = OpenSSL::X509::Revoked.new
    revoked.serial = leaf.serial
    revoked.time = Time.now - 30
    crl.add_revoked(revoked)
    crl.sign(key, nil)
    reject.call(Puppet::SSL::CertVerifyError) { ssl_provider.create_context(**args, private_key: leaf_key) }
  end
end
puts "PASS: #{checks} agent key, CSR, persistence, chain and rejection checks"
