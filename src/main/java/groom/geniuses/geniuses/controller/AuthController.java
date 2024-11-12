package groom.geniuses.geniuses.controller;

import groom.geniuses.dto.LoginRequest;
import groom.geniuses.dto.UserResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final String validUser_id = "id";
    private final String validUser_pw = "password";
    private final String user_name = "닉네임";
    private final String user_profile = "profile.jpg";

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        if (validUser_id.equals(loginRequest.getUser_id()) && validUser_pw.equals(loginRequest.getUser_pw())) {
            UserResponse userResponse = new UserResponse(user_name, user_profile);
            return ResponseEntity.ok(userResponse); // 로그인 성공 시 사용자 정보 반환
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("로그인 실패"); // 로그인 실패
        }
    }
}
