FROM nginxinc/nginx-unprivileged:1.27-alpine3.19-perl

LABEL maintainer="Realize Security Ltd."

USER root

COPY ./certs/fullchain.pem /etc/ssl/
COPY ./certs/privkey.pem /etc/ssl/private/
COPY ./dhparams2048.pem /etc/ssl/certs/dhparams2048.pem
RUN rm /etc/nginx/conf.d/default.conf
COPY ./nginx.conf /etc/nginx/conf.d/nginx.conf
COPY ./ssl-params.conf /etc/nginx/snippets/ssl-params.conf
COPY ./run.sh /run.sh

RUN mkdir -p /vol/log/nginx && \
    chown nginx:nginx /vol/log/nginx && \
    chmod 755 /etc/ssl/fullchain.pem && \
    chmod 755 /etc/ssl/private/privkey.pem && \
    chmod 755 /etc/ssl/certs/dhparams2048.pem && \
    chmod 755 /etc/nginx/snippets/ssl-params.conf && \
    chmod +x /run.sh

VOLUME /vol/log/nginx

USER nginx

CMD ["/run.sh"]