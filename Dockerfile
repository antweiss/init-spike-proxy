FROM gradle:9.7.1-jdk25 AS build
WORKDIR /src
COPY settings.gradle build.gradle ./
COPY src ./src
RUN gradle -q jar --no-daemon

FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /src/build/libs/init-spike-proxy-1.0.0.jar /app/proxy.jar
ENV LISTEN_PORT=8080 \
    CONNECT_PORT=8443 \
    RULE_COUNT=200000 \
    INIT_CPU_PASSES=4 \
    RULE_PAYLOAD_BYTES=256
EXPOSE 8080 8443
RUN groupadd -r proxy 2>/dev/null || true && \
    useradd -r -g proxy proxy 2>/dev/null || true
USER proxy
ENTRYPOINT ["java", "-XX:+UseG1GC", "-jar", "/app/proxy.jar"]
