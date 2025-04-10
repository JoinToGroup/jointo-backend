FROM openjdk:21-jdk

# Copy the built JAR file from the target directory (after Gradle build)
COPY build/libs/*.jar app.jar

# Run the Spring Boot application
ENTRYPOINT ["java", "-jar", "/app.jar"]
