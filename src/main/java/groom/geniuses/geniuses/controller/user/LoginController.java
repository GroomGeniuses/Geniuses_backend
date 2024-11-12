package groom.geniuses.geniuses.controller.user;

import groom.geniuses.geniuses.config.SecurityConfig;
import groom.geniuses.geniuses.dto.user.JoinRequest;
import groom.geniuses.geniuses.service.user.MemberService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.regex.Pattern;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Slf4j
public class LoginController {
    private final MemberService memberService;
    private AuthenticationManager authenticationManager;
    @RequestMapping("/test")
    public ResponseEntity<?> getTest(HttpServletRequest request, HttpServletResponse response){
//        log.info("ATToken : {}", request.getHeader("authorization"));
//        log.info("RTToken : {}", request.getHeader("refreshtoken"));
        log.info("getTest");
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            log.info("cookies exist");
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    log.info("access_token : {}", cookie.getValue());
                }
                else if ("refresh_token".equals(cookie.getName())) {
                    log.info("refresh_token : {}", cookie.getValue());
                }
            }
        }
        HttpHeaders headers = new HttpHeaders();
        return new ResponseEntity<>(headers, HttpStatus.OK);
    }
    @GetMapping("/signup")
    public String joinPage() {
        log.info("GET - /api/auth/signup");
        String redirect = "redirect:" + SecurityConfig.SIGNUP;
        return redirect;
    }
    @ResponseBody
    @PostMapping("/signup")
    // @Valid @ModelAttribute - Content-type : application/x-www-form-urlencoded (form action 전송)
    // @RequestBody [DTO객체] - Content-type : application/json (json data 전송)
    public ResponseEntity<?> join(@RequestBody JoinRequest joinRequest) {
        log.info("POST - /api/auth/signup");
        HttpHeaders headers = new HttpHeaders();
        // ID 중복 여부 확인
        if (memberService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
//            return "ID가 존재합니다.";
            return new ResponseEntity<>("ID가 존재합니다.", headers, HttpStatus.BAD_REQUEST);
        }
        // 비밀번호 = 비밀번호 체크 여부 확인
        if (!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
//            return "비밀번호가 일치하지 않습니다.";
            return new ResponseEntity<>("비밀번호가 일치하지 않습니다.", headers, HttpStatus.BAD_REQUEST);
        }
        // id email 형식인지 체크
        String emailRegex = "^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$";
        if(!Pattern.compile(emailRegex).matcher(joinRequest.getLoginId()).matches()){
//            return "ID가 email 형식이 아닙니다.";
            return new ResponseEntity<>("ID가 email 형식이 아닙니다.", headers, HttpStatus.BAD_REQUEST);
        }
        try{
            // 에러가 존재하지 않을 시 joinRequest 통해서 회원가입 완료
            memberService.securityJoin(joinRequest);
            return new ResponseEntity<>(headers, HttpStatus.CREATED);
        }catch(Exception e){
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        }
    }
//    @ResponseBody
//    @PostMapping("login/form")
//    public ResponseEntity<?> formLogin(@RequestBody JoinRequest joinRequest){
//        log.info("POST - /api/auth/login/form");
//        HttpHeaders headers = new HttpHeaders();
//        if(memberService.formLogin(headers, joinRequest)){
//            return new ResponseEntity<>(headers, HttpStatus.OK);
//        }
//        return new ResponseEntity<>("ID/PW 를 올바르게 입력해주세요", HttpStatus.BAD_REQUEST);
//    }
    @GetMapping("login/google")
    public String googleLogin() {
        String redirect = "redirect:" + SecurityConfig.OAUTH2_GOOGLE;
        log.info("GET - /api/auth/login/oauth2/google - google login\nredirect : {}", redirect);
        return redirect;
    }
    @GetMapping("login/kakao")
    public String kakaoLogin() {
        String redirect = "redirect:" + SecurityConfig.OAUTH2_KAKAO;
        log.info("GET - /api/auth/login/oauth2/kakao - kakao login\nredirect : {}", redirect);
        return redirect;
    }
}