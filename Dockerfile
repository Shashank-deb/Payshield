# syntax=docker/dockerfile:1.6

############################
# Build stage
############################
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app

# Copy POM first (better layer cache)
COPY pom.xml .

# Prime dependency cache
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -e -DskipTests \
      -Dmaven.wagon.http.retryHandler.count=5 \
      -Dmaven.wagon.http.pool=true \
      -Dmaven.wagon.http.timeout=120000 \
      -Dmaven.wagon.http.connectionTimeout=120000 \
      dependency:resolve || true

# Copy sources
COPY src ./src

# Build jar
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -e -U -DskipTests \
      -Dmaven.wagon.http.retryHandler.count=5 \
      -Dmaven.wagon.http.pool=true \
      -Dmaven.wagon.http.timeout=120000 \
      -Dmaven.wagon.http.connectionTimeout=120000 \
      package

############################
# Runtime stage - FIXED PERMISSIONS
############################
FROM eclipse-temurin:21-jre

# Create user and directories with proper permissions
RUN useradd -r -u 10001 -g root appuser \
 && mkdir -p /app /app/tmp /app/logs /app/storage \
 && chown -R appuser:root /app \
 && chmod -R 775 /app

WORKDIR /app
ENV JAVA_OPTS=""
ENV JAVA_TOOL_OPTIONS=""

COPY --from=build /app/target/*.jar /app/app.jar

# Ensure the appuser owns the JAR and can write to directories
RUN chown appuser:root /app/app.jar \
 && chmod 755 /app/app.jar

EXPOSE 2406
USER appuser

# Create storage directories at runtime with proper permissions
RUN mkdir -p /app/tmp/storage /app/logs \
 && chmod -R 755 /app/tmp /app/logs

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]