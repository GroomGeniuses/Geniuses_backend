package groom.geniuses.geniuses.service.user;

import groom.geniuses.geniuses.dao.user.Member;
import groom.geniuses.geniuses.dao.user.MemberRepository;
import groom.geniuses.geniuses.dto.user.JoinRequest;
import groom.geniuses.geniuses.jwt.JWTUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class MemberService {
    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JWTUtil jwtUtil;
    public boolean checkLoginIdDuplicate(String loginId){
        log.info("checkLoginIdDuplicate() - loginId : {}", loginId);
        return memberRepository.existsByUserId(loginId);
    }
    // BCryptPasswordEncoder 를 통해서 비밀번호 암호화 작업 추가한 회원가입 로직
    public void securityJoin(JoinRequest joinRequest){
        log.info("securityJoin() - joinRequest : {}", joinRequest);
        joinRequest.setPassword(bCryptPasswordEncoder.encode(joinRequest.getPassword()));
        memberRepository.save(joinRequest.toEntity());
    }
    public boolean formLogin(HttpHeaders headers, JoinRequest joinRequest){
        log.info("formLogin() - joinRequest : {}", joinRequest);
        Member member = memberRepository.findByUserId(joinRequest.getLoginId());
        if(member==null || !bCryptPasswordEncoder.matches(joinRequest.getPassword(), member.getPassword())){
            return false;
        }

        String accessToken = jwtUtil.createAccessToken(member.getUserId(), member.getUserId(), member.getRole().name());
        String refreshToken = jwtUtil.createRefreshToken();
        headers.add("Authorization", "Bearer " + accessToken);
        headers.add("RefreshToken", "Bearer " + refreshToken);
        return true;
    }
}