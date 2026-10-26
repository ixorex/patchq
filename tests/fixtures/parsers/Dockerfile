ARG BASE=python:3.12-slim
FROM node:18-alpine AS build
RUN npm ci
FROM --platform=linux/amd64 python:3.11-slim-bookworm
COPY --from=build /app /app
FROM build AS test
FROM scratch
