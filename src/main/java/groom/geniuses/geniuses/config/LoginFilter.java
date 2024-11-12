package groom.geniuses.geniuses.config;

import groom.geniuses.geniuses.jwt.FormUserDetails;
import groom.geniuses.geniuses.jwt.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("Authentication start");
//        if ("application/json".equals(request.getContentType())) {
//            log.info("Authentication application/json true");
//            try {
//                @SuppressWarnings("unchecked")
//                Map<String, String> authRequest = (new ObjectMapper()).readValue(request.getInputStream(), Map.class);
//                log.info("authRequest");
//                String loginId = authRequest.get("loginId");
//                log.info("loginId");
//                String password = authRequest.get("password");
//                log.info("password");
//                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(loginId, password);
//                log.info("UsernamePasswordAuthenticationToken");
//                log.info("attemptAuthentication request\nloginId/password: {} / {}", loginId, password);
//                return authenticationManager.authenticate(authToken);
//            } catch (IOException e) {
//                log.info("IOException");
//                throw new RuntimeException(e);
//            }
//        }
        String path = request.getRequestURI();
        log.info("Authentication attemptAuthentication() api uri: {}", path);
        String loginId = obtainUsername(request);
        String password = obtainPassword(request);
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(loginId, password, null);
        return authenticationManager.authenticate(authToken);
    }
    // 로그인 성공 시
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        log.info("void successfulAuthentication()");
        // username 추출
        FormUserDetails formUserDetails = (FormUserDetails) authentication.getPrincipal();
        // role 추출
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
        String username = formUserDetails.getUsername();
        String id = formUserDetails.getPKId();
        // JWTUtil에 token 생성 요청
        String accessToken = jwtUtil.createAccessToken(id, username, role);
        String refreshToken = jwtUtil.createRefreshToken();
        // JWT를 response에 담아서 응답 (header 부분에)
        // key : "Authorization"
        // value : "Bearer " (인증방식) + token
        response.addHeader("Authorization", "Bearer " + accessToken);
        response.addHeader("RefreshToken", "Bearer " + refreshToken);
        log.info("Authorization : Bearer {}\nRefreshToken : Bearer {}", accessToken, refreshToken);
    }
    // 로그인 실패 시
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        // 실패 시 401 응답코드 보냄
        response.setStatus(401);
    }
}