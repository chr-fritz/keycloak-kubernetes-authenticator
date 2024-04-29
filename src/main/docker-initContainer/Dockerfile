FROM busybox:latest

COPY build/libs/keycloak-kubernetes-authenticator.jar /keycloak-kubernetes-authenticator.jar
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
