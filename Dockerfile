FROM elixir:1.18-otp-27

# Set working directory
WORKDIR /app

# Copy project files
COPY mix.exs mix.lock ./
COPY lib lib
COPY test test

# Install hex and rebar
RUN mix local.hex --force && mix local.rebar --force

# Get dependencies
RUN mix deps.get

# Compile project
RUN mix deps.compile

# Set environment for tests
ENV MIX_ENV=test

# Run all tests including integration tests
CMD ["mix", "test", "--include", "integration"]