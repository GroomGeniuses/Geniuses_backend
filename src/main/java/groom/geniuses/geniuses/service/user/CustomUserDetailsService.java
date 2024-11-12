package groom.geniuses.geniuses.service.user;

import groom.geniuses.geniuses.dao.user.Member;
import groom.geniuses.geniuses.dao.user.MemberRepository;
import groom.geniuses.geniuses.jwt.FormUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;
    @Override
    public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        log.info("UserDetails loadUserByUsername() - username(loginId) : {}", loginId);
        Member member = memberRepository.findByUserId(loginId);
        if(member != null) {
            return new FormUserDetails(member);
        }
        return null;
    }
}