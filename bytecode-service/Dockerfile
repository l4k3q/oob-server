FROM eclipse-temurin:17-jdk-jammy AS build
WORKDIR /src

# Install Maven
RUN apt-get update -q && \
    apt-get install -y --no-install-recommends maven && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install java-chains JARs into local Maven repo
COPY libs/chains-jars ./chains-jars
RUN mvn install:install-file -q \
      -Dfile=chains-jars/chains-parent.pom.xml \
      -DgroupId=com.ar3h -DartifactId=chains -Dversion=1.4.4 -Dpackaging=pom && \
    mvn install:install-file -q \
      -Dfile=chains-jars/chains-core-1.4.4.jar \
      -DgroupId=com.ar3h -DartifactId=chains-core -Dversion=1.4.4 -Dpackaging=jar && \
    mvn install:install-file -q \
      -Dfile=chains-jars/chains-common-1.4.4.jar \
      -DgroupId=com.ar3h -DartifactId=chains-common -Dversion=1.4.4 -Dpackaging=jar && \
    mvn install:install-file -q \
      -Dfile=chains-jars/chains-plugin-api-1.4.4.jar \
      -DgroupId=com.ar3h -DartifactId=chains-plugin-api -Dversion=1.4.4 -Dpackaging=jar && \
    mvn install:install-file -q \
      -Dfile=chains-jars/chains-thirdparty-1.4.4.jar \
      -DgroupId=com.ar3h -DartifactId=chains-thirdparty -Dversion=1.4.4 -Dpackaging=jar

COPY pom.xml .
RUN mvn dependency:go-offline -q 2>/dev/null || true

COPY src ./src
RUN mvn package -DskipTests -q

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Java 8 for ysoserial/marshalsec subprocess + curl for healthcheck
RUN apt-get update -q && \
    apt-get install -y --no-install-recommends openjdk-8-jre-headless curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/bytecode-service-0.1.0.jar .
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
# java-chains runs co-located in the same container on port 8011
ENV JAVACHAINS_URL=http://127.0.0.1:8011

EXPOSE 8711
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=40s \
  CMD curl -fsS http://localhost:8711/chains || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
