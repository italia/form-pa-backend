FROM php:7.4-cli

# https://github.com/hadolint/hadolint/wiki/DL4006
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN adduser --system --group form-pa-backend \
  \
  && mkdir -p /app/vendor/bundle \
  && chown -R form-pa-backend:form-pa-backend /app

RUN apt-get update \
    && apt-get install -y git unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
  && composer install

# COPY --chown=form-pa-backend:form-pa-backend . ./
# COPY --from=build --chown=form-pa-backend:form-pa-backend /usr/local/bundle /usr/local/bundle

# COPY docker/entrypoint.sh /usr/local/bin/
# RUN chmod +x /usr/local/bin/entrypoint.sh

USER form-pa-backend

# ENTRYPOINT ["entrypoint.sh"]
CMD ["php", "-S", "0.0.0.0:8000", "-t", "public"]

EXPOSE 8000
