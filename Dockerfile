# syntax=docker/dockerfile:1.6

############################
# Build stage
############################
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app

# Copy POM first (better layer cache)
COPY pom.xml .

# (Optional) prime dependency cache by running a no-op resolve WITHOUT custom -s
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -e -DskipTests \
      -Dmaven.wagon.http.retryHandler.count=5 \
      -Dmaven.wagon.http.pool=true \
      -Dmaven.wagon.http.timeout=120000 \
      -Dmaven.wagon.http.connectionTimeout=120000 \
      dependency:resolve || true

# Copy sources
COPY src ./src

# Build jar (no -s)
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -e -U -DskipTests \
      -Dmaven.wagon.http.retryHandler.count=5 \
      -Dmaven.wagon.http.pool=true \
      -Dmaven.wagon.http.timeout=120000 \
      -Dmaven.wagon.http.connectionTimeout=120000 \
      package

############################
# Runtime stage (non-root)
############################
FROM eclipse-temurin:21-jre

RUN useradd -r -u 10001 -g root appuser \
 && mkdir -p /app /app/tmp \
 && chown -R appuser:root /app

WORKDIR /app
ENV JAVA_OPTS=""
ENV JAVA_TOOL_OPTIONS=""

COPY --from=build /app/target/*.jar /app/app.jar

EXPOSE 2406
USER appuser
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
