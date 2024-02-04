FROM debian:12

# Set timezone
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Update
RUN apt-get update && apt-get dist-upgrade -y

# Install composer
RUN apt-get update && apt-get install composer -y

WORKDIR /srv

# Composer dependencies
RUN apt-get install -y \
  php8.2-phar \
  php8.2-iconv \
  php8.2-mbstring \
  php8.2-curl \
  php8.2-ctype \
  php8.2-opcache \
  php8.2-sockets \
  php8.2-simplexml \
  php8.2-dom \
  php8.2-tokenizer \
  php8.2-apcu \
  php8.2-posix \
  php8.2-xmlwriter \
  php8.2-xml \
  php8.2-zip \
  php8.2-ftp \
  ca-certificates

RUN echo "opcache.enable_cli=1" > /etc/php/8.2/cli/conf.d/opcache.ini \
  && echo "opcache.file_cache='/tmp/opcache'" >> /etc/php/8.2/cli/conf.d/opcache.ini \
  && echo "opcache.file_update_protection=0" >> /etc/php/8.2/cli/conf.d/opcache.ini \
  && mkdir /tmp/opcache

COPY composer.json /srv/

RUN composer install --no-dev --no-scripts --optimize-autoloader \
   && composer require "daverandom/libdns:^2.0.1" --no-scripts --no-suggest --optimize-autoloader

COPY ./src /srv/src
#COPY ./res /srv/res
COPY ./bin /srv/bin

#RUN composer warmup-opcode -- /srv

RUN echo "date.timezone = UTC" > /etc/php/8.2/cli/conf.d//symfony.ini \
 && echo "opcache.enable_cli=1" > /etc/php/8.2/cli/conf.d//opcache.ini \
 && echo "opcache.file_cache='/tmp/opcache'" >> /etc/php/8.2/cli/conf.d/opcache.ini \
 && echo "opcache.file_update_protection=0" >> /etc/php/8.2/cli/conf.d/opcache.ini

ENTRYPOINT ["/srv/bin/acme"]
CMD ["list"]
