package groom.geniuses.geniuses.service.user;

import groom.geniuses.geniuses.dao.user.Member;
import groom.geniuses.geniuses.dao.user.MemberRepository;
import groom.geniuses.geniuses.dao.user.MemberRole;
import groom.geniuses.geniuses.jwt.CustomOauth2UserDetails;
import groom.geniuses.geniuses.jwt.oauth2.GoogleUserDetails;
import groom.geniuses.geniuses.jwt.oauth2.KakaoUserDetails;
import groom.geniuses.geniuses.jwt.oauth2.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOauth2UserDetailsService extends DefaultOAuth2UserService {
    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("OAuth2User loadUser() - getAttributes : {}", oAuth2User.getAttributes());
        String provider = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = null;
        // 소셜 서비스 로그인 구분
        switch(provider){
            case "google":
                log.info("구글 로그인");
                oAuth2UserInfo = new GoogleUserDetails(oAuth2User.getAttributes());
                break;
            case "kakao":
                log.info("카카오 로그인");
                oAuth2UserInfo = new KakaoUserDetails(oAuth2User.getAttributes());
                break;
        }
        String providerId = oAuth2UserInfo.getProviderId();
        String loginId = oAuth2UserInfo.getEmail();
        String email = oAuth2UserInfo.getEmail();
        String name = oAuth2UserInfo.getName();
        String image = oAuth2UserInfo.getImage();
        Member findMember = memberRepository.findByUserId(loginId);
        Member member;
        log.info("loginId : {}", loginId);
        if (findMember == null) {
            member = Member.builder()
                    .userId(loginId)
                    .userName(name)
                    .image(image)
//                    .email(email)
                    .provider(provider)
                    .providerId(providerId)
                    .role(MemberRole.USER)
//                    .createdUserDate(new Date())
                    .build();
            memberRepository.save(member);
        } else{
            member = findMember;
        }
        return new CustomOauth2UserDetails(member, oAuth2User.getAttributes());
    }
}