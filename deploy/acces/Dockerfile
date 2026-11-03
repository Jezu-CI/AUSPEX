# Front HTTPS du central Auspex (nginx sans privilèges).
#   - HTTPS devant NetBox (certificat de config/tls/, autosigné à l'installation
#     ou fourni par l'exploitant) ;
#   - port carte à puce, si auth.carte est configurée : certificat client exigé
#     et vérifié (autorités des cartes, révocation), transmis à NetBox avec un
#     secret partagé.
FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY deploy/acces/nginx.conf /etc/auspex-acces-image/nginx.conf
COPY deploy/acces/entrypoint.sh /usr/local/bin/auspex-acces

LABEL org.opencontainers.image.title="auspex-acces" \
      org.opencontainers.image.description="Front HTTPS du central Auspex (TLS, carte à puce)" \
      org.opencontainers.image.licenses="Apache-2.0"

EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/auspex-acces"]
