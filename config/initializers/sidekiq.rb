# frozen_string_literal: true

require 'sidekiq/web' if defined?(Puma)

if !ENV['SIDEKIQ_BASIC_AUTH_PASSWORD'].to_s.empty? && defined?(Sidekiq::Web)
  Sidekiq::Web.use(Rack::Auth::Basic) do |_, password|
    ActiveSupport::SecurityUtils.secure_compare(
      Digest::SHA256.hexdigest(password),
      Digest::SHA256.hexdigest(ENV.fetch('SIDEKIQ_BASIC_AUTH_PASSWORD'))
    )
  end
end

Sidekiq.strict_args!

Sidekiq.configure_server do |config|
  config.death_handlers << lambda { |job, ex|
    Rails.logger.error(
      "[Sidekiq] Job exhausted retries: class=#{job['class']} " \
      "error=#{ex.class}: #{ex.message} " \
      "args=#{job['args'].inspect}"
    )
    Rollbar.error(ex, sidekiq_job: job.slice('class', 'args', 'queue')) if defined?(Rollbar)
  }
end
