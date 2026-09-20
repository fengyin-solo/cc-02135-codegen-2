FROM --platform=$BUILDPLATFORM nginx:alpine

COPY index.html /usr/share/nginx/html/
COPY audit.html /usr/share/nginx/html/
COPY style.css /usr/share/nginx/html/
COPY audit.css /usr/share/nginx/html/
COPY app.js /usr/share/nginx/html/
COPY audit.js /usr/share/nginx/html/
COPY config.js /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
