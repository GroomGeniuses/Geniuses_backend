package groom.geniuses.geniuses.config;

import groom.geniuses.geniuses.dao.user.Member;
import groom.geniuses.geniuses.dao.user.MemberRole;
import groom.geniuses.geniuses.jwt.FormUserDetails;
import groom.geniuses.geniuses.jwt.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;

@RequiredArgsConstructor
@Slf4j
public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        log.info("void doFilterInternal() - api uri : {}", path);
        String authorization = null;
        String refreshToken = null;
        // Authorization Cookie 찾음
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    authorization = cookie.getValue();
                }
                else if ("refresh_token".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }
        }
        // access_token 검증
        // authorization 가 비어있거나 "Bearer " 로 시작하지 않은 경우
        if(isInvalid(request, response, filterChain, authorization)){
            // 메서드 종료
            return;
        }
        // Authorization에서 Bearer 접두사 제거
        String token = authorization.split("\\+")[1];
        String id = jwtUtil.getPKId(token);
        String nickname = jwtUtil.getNickname(token);
        String role = jwtUtil.getRole(token);

        // accessToken 소멸 시간 검증
        // accessToken 유효기간이 만료한 경우
        if(jwtUtil.isExpired(token)){
            log.warn("accessToken expired");
            // refresh_token 검증
            // refreshToken 비어있거나 "Bearer " 로 시작하지 않은 경우
            if (isInvalid(request, response, filterChain, refreshToken)){
                // 메서드 종료
                return;
            }
            // refreshToken 소멸 시간 검증
            // refreshToken 유효기간이 만료한 경우
            if(jwtUtil.isExpired(refreshToken)){
                log.warn("refreshToken expired");
                filterChain.doFilter(request, response);
                // 메서드 종료
                return;
            }
            // accessToken 재발급
            token = jwtUtil.createAccessToken(id, nickname, role);

            Cookie atCookie = new Cookie("access_token", URLEncoder.encode("Bearer " + token, "utf-8"));
            atCookie.setHttpOnly(true); // HttpOnly 설정
            atCookie.setSecure(true);
            atCookie.setPath("/"); // 모든 경로에서 접근 가능
            atCookie.setMaxAge(60 * 60 * 24); // 만료 시간 (예: 24시간)
            response.addCookie(atCookie);
        }

        // 최종적으로 token 검증 완료 => 일시적인 session 생성
        // session에 user 정보 설정
        Member member = new Member();
        member.setUserId(id);
        // 매번 요청마다 DB 조회해서 password 초기화 할 필요 x => 정확한 비밀번호 넣을 필요 없음
        // 따라서 임시 비밀번호 설정!
        member.setPassword("임시 비밀번호");
        member.setRole(MemberRole.valueOf(role));
        // UserDetails에 회원 정보 객체 담기
        FormUserDetails formUserDetails = new FormUserDetails(member);
        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(formUserDetails, null, formUserDetails.getAuthorities());
        // 세션에 사용자 등록 => 일시적으로 user 세션 생성
        SecurityContextHolder.getContext().setAuthentication(authToken);
        // 다음 필터로 request, response 넘겨줌
        filterChain.doFilter(request, response);

        // jwt response header 저장
//        // request에서 Authorization 헤더 찾음
//        String authorization = request.getHeader("Authorization");
//        // Authorization 헤더 검증
//        // Authorization 헤더가 비어있거나 "Bearer " 로 시작하지 않은 경우
//        if(isInvalid(request, response, filterChain, authorization)){
//            // 메서드 종료
//            return;
//        }
//        // Authorization에서 Bearer 접두사 제거
//        String token = authorization.split(" ")[1];
//        String id = jwtUtil.getPKId(token);
//        String nickname = jwtUtil.getNickname(token);
//        String role = jwtUtil.getRole(token);
//
//        // accessToken 소멸 시간 검증
//        // accessToken 유효기간이 만료한 경우
//        if(jwtUtil.isExpired(token)){
//            log.warn("accessToken expired");
//            String refreshToken = request.getHeader("RefreshToken");
//            // RefreshToken 헤더 검증
//            // RefreshToken 헤더가 비어있거나 "Bearer " 로 시작하지 않은 경우
//            if (isInvalid(request, response, filterChain, refreshToken)){
//                // 메서드 종료
//                return;
//            }
//            // refreshToken 소멸 시간 검증
//            // refreshToken 유효기간이 만료한 경우
//            if(jwtUtil.isExpired(refreshToken)){
//                log.warn("refreshToken expired");
//                filterChain.doFilter(request, response);
//                // 메서드 종료
//                return;
//            }
//            // accessToken 재발급
//            token = jwtUtil.createAccessToken(id, nickname, role);
//            response.addHeader("Authorization", "Bearer " + token);
//        }
//
//        // 최종적으로 token 검증 완료 => 일시적인 session 생성
//        // session에 user 정보 설정
//        Member member = new Member();
//        member.setUserId(id);
//        // 매번 요청마다 DB 조회해서 password 초기화 할 필요 x => 정확한 비밀번호 넣을 필요 없음
//        // 따라서 임시 비밀번호 설정!
//        member.setPassword("임시 비밀번호");
//        member.setRole(MemberRole.valueOf(role));
//        // UserDetails에 회원 정보 객체 담기
//        FormUserDetails formUserDetails = new FormUserDetails(member);
//        // 스프링 시큐리티 인증 토큰 생성
//        Authentication authToken = new UsernamePasswordAuthenticationToken(formUserDetails, null, formUserDetails.getAuthorities());
//        // 세션에 사용자 등록 => 일시적으로 user 세션 생성
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//        // 다음 필터로 request, response 넘겨줌
//        filterChain.doFilter(request, response);
    }

    private boolean isInvalid(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String token) throws IOException, ServletException {
        if(token == null || !token.startsWith("Bearer")){
            log.warn("token null || token doesn't start with 'Bearer'");
            // 토큰이 유효하지 않으므로 request와 response를 다음 필터로 넘겨줌
            filterChain.doFilter(request, response);
            return true;
        }
        return false;
    }
}
