FROM maven:3.8-openjdk-8 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q dependency:go-offline
COPY src ./src
RUN mvn -q package -DskipTests

FROM openjdk:8-jre-slim
WORKDIR /app
COPY --from=build /app/target/shiro-app-1.0.jar app.jar
EXPOSE 8080
ENV PORT=8080
ENV SHIRO_KEY=kPH+bIxk5D2deZiIxcaaaA==
CMD ["java", "-jar", "app.jar"]
