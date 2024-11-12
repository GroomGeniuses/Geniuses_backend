# https://velog.io/@g6y116/5
# OpenJDK 17을 기반으로 하는 경량화 스프링 부트 이미지
# FROM openjdk:17-alpine
FROM bellsoft/liberica-openjdk-alpine:17
# 작업 디렉토리 설정
WORKDIR /app/backend
# JAR 파일을 컨테이너에 복사(jar파일이 하나만 생기도록 설정해줘야 함.)
COPY build/libs/*.jar app.jar
# # 환경변수
# COPY .env ./
# RUN export $(cat .env | xargs)
# 포트 설정
EXPOSE 8080
# 실행 명령어
ENTRYPOINT ["java", "-jar", "app.jar"]