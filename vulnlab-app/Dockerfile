FROM openjdk:8-jre-slim
RUN apt-get update -qq && apt-get install -y --no-install-recommends curl wget ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY target/vulnlab-app-1.0.jar vulnlab.jar
EXPOSE 8888
ENTRYPOINT ["java", \
  "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", \
  "-Dlog4j2.formatMsgNoLookups=false", \
  "-jar", "vulnlab.jar"]
