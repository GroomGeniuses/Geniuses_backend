package groom.geniuses.geniuses.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig {
//public class WebConfig implements WebMvcConfigurer {
//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**")
//                .allowedOrigins("http://localhost:3000", "http://localhost:8080", DOMAIN) // 허용할 출처
//                .allowedMethods("GET", "POST", "PATCH", "PUT", "DELETE", "OPSTIONS") // 허용할 HTTP method
//                .allowedHeaders("Authorization", "RefreshToken", "Content-Type")
//                .allowCredentials(true) // 쿠키 인증 요청 허용
//                .maxAge(3000); // 원하는 시간만큼 pre-flight 리퀘스트를 캐싱
//    }
}