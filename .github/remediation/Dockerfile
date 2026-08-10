FROM php:8.1-apache

RUN docker-php-ext-install mysqli \
    && docker-php-ext-enable mysqli \
    && a2enmod rewrite ssl headers \
    && echo 'ServerName 127.0.0.1' > /etc/apache2/conf-available/courier-servername.conf \
    && a2enconf courier-servername

WORKDIR /var/www/html
COPY . /var/www/html/

COPY docker/remediation/php.ini /usr/local/etc/php/conf.d/courier-remediation.ini
COPY docker/remediation/apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY docker/remediation/apache/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf
COPY docker/remediation/certs/server.crt /etc/ssl/certs/courier-remediation.crt
COPY docker/remediation/certs/server.key /etc/ssl/private/courier-remediation.key

RUN a2ensite default-ssl \
    && mkdir -p /var/www/html/server/uploads \
    && chown -R www-data:www-data /var/www/html/server/uploads \
    && chmod 0644 /etc/ssl/certs/courier-remediation.crt \
    && chmod 0600 /etc/ssl/private/courier-remediation.key

EXPOSE 80 443
