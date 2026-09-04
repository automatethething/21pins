#!/usr/bin/env ruby
path = File.join(__dir__, 'Formula', '21pins.rb.template')
text = File.read(path)
required = %w[{{VERSION}} {{DARWIN_ARM64_SHA256}} {{DARWIN_AMD64_SHA256}} {{LINUX_ARM64_SHA256}} {{LINUX_AMD64_SHA256}}]
missing = required.reject { |placeholder| text.include?(placeholder) }
abort "missing placeholders: #{missing.join(', ')}" unless missing.empty?
abort 'formula must isolate test state with PINS21_STATE_PATH' unless text.include?('PINS21_STATE_PATH')
abort 'formula must install 21pins binary' unless text.include?('bin.install "21pins"')
puts 'homebrew formula template checks pass'
