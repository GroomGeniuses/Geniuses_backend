package groom.geniuses.geniuses.config;

import groom.geniuses.geniuses.dao.user.MemberRole;
import groom.geniuses.geniuses.jwt.CustomUserDetails;
import groom.geniuses.geniuses.jwt.JWTUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    public static final String DOMAIN = "http://localhost:3000"; // 로컬용
//    public static final String DOMAIN = "[도메인]"; // 배포용
    public static final String HOME = DOMAIN;
    public static final String LOGIN = DOMAIN + "/login";
    public static final String SIGNUP = DOMAIN + "/signup";
    public static final String OAUTH2_GOOGLE = "/oauth2/authorization/google";
    public static final String OAUTH2_KAKAO = "/oauth2/authorization/kakao";


    private final AuthenticationConfiguration configuration;
    private final JWTUtil jwtUtil;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){ return new BCryptPasswordEncoder(); }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(List.of("http://localhost:3000", SecurityConfig.DOMAIN));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedHeaders(List.of("Authorization", "RefreshToken", "Content-Type"));
        corsConfiguration.addExposedHeader("Authorization");
        corsConfiguration.addExposedHeader("RefreshToken");
        corsConfiguration.addExposedHeader("Content-Type");
        corsConfiguration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        // cors
        http.cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()));
        // 같은 origin에서 접근 허용
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        // api 접근 권한 설정
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers(HttpMethod.DELETE, "/api/auth/test").hasAuthority(MemberRole.ADMIN.name()) // ADMIN 권한시 가능
                .requestMatchers(HttpMethod.PUT, "/api/auth/test").hasAuthority(MemberRole.USER.name()) // USER 권한시 가능
                .requestMatchers(HttpMethod.PATCH, "/api/auth/test").hasAuthority(MemberRole.USER.name()) // USER 권한시 가능
                .requestMatchers(HttpMethod.POST, "/api/auth/test").authenticated() // 로그인시가능
                .requestMatchers(HttpMethod.GET, "/api/auth/test").permitAll() // 모두가능
                .requestMatchers(PathRequest.toH2Console()).permitAll() // h2console 접근 모두 허용
                // [/**] : 뒤에 붙은 모든 경로 포함
//                .requestMatchers(HttpMethod.[GET/POST/PATCH/PUT/DELETE], domain + "[api uri]/**").hasAuthority(MemberRole.ADMIN.name()) // 권한지정
//                .requestMatchers(HttpMethod.[GET/POST/PATCH/PUT/DELETE], domain + "[api uri]/**").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능
                .anyRequest().permitAll());
        // 폼 로그인 방식 설정
//        http.formLogin((auth)-> auth.disable());
        http.formLogin((auth) -> auth
                .loginPage(SecurityConfig.LOGIN)
                .loginProcessingUrl("/api/auth/login/form")
                .usernameParameter("loginId")
                .passwordParameter("password")
                .defaultSuccessUrl(SecurityConfig.HOME)
                .successHandler((request, response, authentication)->{
                    log.info("formLogin successHandler auth");
//                    setJWT(response, authentication);
                    setJWTCookie(response, authentication);
                    response.sendRedirect(SecurityConfig.HOME);
                })
                .failureUrl("/oauth2-login/login")
                .failureHandler((request, response, authentication)->{
                    log.info("formLogin failureHandler\nrequest : {}\nresponse : {}\nauthentication : {}\n\n", request, response, authentication);
                    response.sendRedirect(SecurityConfig.LOGIN);
                })
                .permitAll());
        // OAuth 2.0 로그인 방식 설정
        http.oauth2Login((auth) -> auth
                .loginPage(SecurityConfig.LOGIN)
                .defaultSuccessUrl(SecurityConfig.HOME)
                .successHandler((request, response, authentication)->{
                    log.info("oauth2Login successHandler auth");
//                    setJWT(response, authentication);
                    setJWTCookie(response, authentication);
                    response.sendRedirect(SecurityConfig.HOME);
                })
                .failureUrl(SecurityConfig.LOGIN)
                .failureHandler((request, response, authentication)->{
                    log.info("oauth2Login failureHandler\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, authentication);
                    response.sendRedirect(SecurityConfig.LOGIN);
                })
                .permitAll());
        // 로그아웃 URL 설정
        http.logout((auth) -> auth
//                .logoutUrl("[api logout uri]")
                .logoutSuccessUrl(SecurityConfig.HOME)); // 로그아웃 성공 시 redirect
        // csrf : 사이트 위변조 방지 설정 (스프링 시큐리티에는 자동으로 설정 되어 있음)
        // csrf기능 켜져있으면 post 요청을 보낼때 csrf 토큰도 보내줘야 로그인 진행됨 !
        // 개발단계에서만 csrf 잠시 꺼두기
        http.csrf((auth) -> auth.disable());
        // http basic 인증 방식 disable 설정
        http.httpBasic((auth -> auth.disable()));
        // 세션 설정
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // 새로 만든 로그인 필터를 원래의 (UsernamePasswordAuthenticationFilter)의 자리에 넣음
        http.addFilterAt(new LoginFilter(authenticationManager(configuration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
        // LoginFilter 이전에 JWTFilter를 넣음
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        return http.build();
    }
    private void setJWTCookie(HttpServletResponse response, Authentication authentication) throws UnsupportedEncodingException {
        CustomUserDetails principal = (CustomUserDetails) authentication.getPrincipal();
        // AT RT 생성
        String id = principal.getPKId();
        String loginId = principal.getUsername();
        String memberRole = principal.getRole().name();
        String accessToken = jwtUtil.createAccessToken(id, loginId, memberRole);
        String refreshToken = jwtUtil.createRefreshToken();

        Cookie atCookie = new Cookie("access_token", URLEncoder.encode("Bearer " + accessToken, "utf-8"));
        Cookie rtCookie = new Cookie("refresh_token", URLEncoder.encode("Bearer " + refreshToken, "utf-8"));
        atCookie.setHttpOnly(true); // HttpOnly 설정
        atCookie.setSecure(true);
        atCookie.setPath("/"); // 모든 경로에서 접근 가능
        atCookie.setMaxAge(60 * 60 * 24); // 만료 시간 (예: 24시간)
        rtCookie.setHttpOnly(true); // HttpOnly 설정
        atCookie.setSecure(true);
        rtCookie.setPath("/"); // 모든 경로에서 접근 가능
        rtCookie.setMaxAge(60 * 60 * 24); // 만료 시간 (예: 24시간)
        response.addCookie(atCookie);
        response.addCookie(rtCookie);
    }
//    private void setJWT(HttpServletResponse response, Authentication authentication) {
//        CustomUserDetails principal = (CustomUserDetails) authentication.getPrincipal();
//        // AT RT 생성
//        String id = principal.getPKId();
//        String loginId = principal.getUsername();
//        String memberRole = principal.getRole().name();
//        String accessToken = jwtUtil.createAccessToken(id, loginId, memberRole);
//        String refreshToken = jwtUtil.createRefreshToken();
//
//        response.addHeader("Authorization", "Bearer " + accessToken);
//        response.addHeader("RefreshToken", "Bearer " + refreshToken);
//    }
}