FROM maven:3.8.6-openjdk-8 AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

FROM eclipse-temurin:8-jre-jammy
RUN apt-get update -qq && apt-get install -y --no-install-recommends curl wget ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/vulnlab-app-1.0.jar vulnlab.jar
EXPOSE 8888
ENTRYPOINT ["java", \
  "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", \
  "-Dlog4j2.formatMsgNoLookups=false", \
  "-jar", "vulnlab.jar"]
