# The Agent Guard sample MCP server, as a container that speaks MCP over stdio.
#
#   docker build -t agent-guard-sample .
#   docker run -i --rm agent-guard-sample
#
# It is at the repository root because MCP directories (Glama) build the root Dockerfile,
# start the container with `docker run -i`, and call tools/list to list and score the server.
# tools/check-sample-container.sh runs that same check, and CI runs the script on every pull
# request ("Sample container").
#
# This image is for introspection and a quick look, not a deployment:
# - Profile "stdio" (agent-guard-sample/src/main/resources/application-stdio.yml): no HTTP
#   server, no database, decisions and audit in memory. tools/list answers; every tool call is
#   refused, because a stdio caller has no authenticated principal. For the full approval
#   round trip, run the sample with PostgreSQL as its README shows.
# - No port and no HEALTHCHECK: the server has no HTTP endpoint in this profile, and a process
#   that answers on stdin cannot be probed from a second process without becoming a client.
# - No secret, no environment variable needed to start.
#
# Both base images are pinned by digest (multi-architecture index). The jar is built here from
# this source tree, never downloaded; Maven itself comes from the wrapper, which verifies the
# distribution against the SHA-256 in .mvn/wrapper/maven-wrapper.properties.

FROM eclipse-temurin:21-jdk-noble@sha256:57424b1d8eca9c4cf8a4fe226207027911f08d6758628891bf59fcfb53777029 AS build
# unzip: without it the wrapper falls back to the .tar.gz distribution, whose SHA-256 is not the
# one recorded for the .zip, and refuses to run (correctly). Build stage only; not in the image.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends unzip
WORKDIR /src
COPY . .
# Tests are not run in the image build: they need Docker (Testcontainers) and run in CI
# ("Build & test"). package still compiles with Error Prone and repackages the sample jar.
RUN ./mvnw -B -ntp -pl agent-guard-sample -am -DskipTests package \
    && jars="$(ls agent-guard-sample/target/agent-guard-sample-*.jar)" \
    && [ "$(printf '%s\n' "$jars" | wc -l)" -eq 1 ] \
    && cp "$jars" /src/app.jar

FROM eclipse-temurin:21-jre-noble@sha256:cd35bb33859641c5374415826a5951845104093eaa401cbe9d3d9023444f1c13
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=build --chown=root:root /src/app.jar /app/app.jar
COPY --from=build --chown=root:root /src/LICENSE /src/NOTICE /app/
USER 10001:10001
ENV SPRING_PROFILES_ACTIVE=stdio
CMD ["java", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
