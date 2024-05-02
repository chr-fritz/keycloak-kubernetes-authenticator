FROM busybox:latest

COPY build/libs/keycloak-kubernetes-authenticator.jar /keycloak-kubernetes-authenticator.jar
COPY --chmod=755 src/main/docker-initContainer/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
