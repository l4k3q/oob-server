FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

FROM azul/zulu-openjdk:7 AS zulu7

FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app

# Java 8 for ysoserial/marshalsec subprocess + curl for healthcheck
RUN apt-get update -q && \
    apt-get install -y --no-install-recommends openjdk-8-jdk-headless curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Java 7 (Zulu) for ysoserial_jdk7u21: AnnotationInvocationHandler serialVersionUID matches Java 7 target
COPY --from=zulu7 /usr/lib/jvm/zulu-7-amd64 /opt/zulu7

COPY --from=builder /build/target/bytecode-service-0.1.0.jar .
COPY libs ./libs

# Extract java-chains binary (bundles its own JDK) to /opt/java-chains
RUN if [ -f /app/libs/java-chains-linux-amd64.tar.gz ]; then \
      mkdir -p /opt/java-chains && \
      tar -xzf /app/libs/java-chains-linux-amd64.tar.gz \
          --strip-components=1 -C /opt/java-chains && \
      echo "[Docker] java-chains extracted to /opt/java-chains"; \
    fi

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV YSOSERIAL_JAVA=/usr/lib/jvm/java-8-openjdk-amd64/bin/java
ENV YSOSERIAL_JAVA_7=/opt/zulu7/bin/java
# java-chains runs co-located in the same container on port 8011
ENV JAVACHAINS_URL=http://127.0.0.1:8011

EXPOSE 8711
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=40s \
  CMD curl -fsS http://localhost:8711/chains || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
