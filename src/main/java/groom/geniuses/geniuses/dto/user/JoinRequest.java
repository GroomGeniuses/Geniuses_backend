package groom.geniuses.geniuses.dto.user;

import groom.geniuses.geniuses.dao.user.Member;
import groom.geniuses.geniuses.dao.user.MemberRole;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
public class JoinRequest {
    private String nickname;
    @NotBlank(message = "ID를 입력하세요.")
    private String loginId;
    @NotBlank(message = "비밀번호를 입력하세요.")
    private String password;
    private String passwordCheck;
    private String introduce;

    public Member toEntity(){
        return Member.builder()
                .userId(this.loginId)
                .password(this.password)
                .userName(this.nickname)
//                .email(this.loginId)
                .role(MemberRole.USER)
                .introduce(this.introduce)
//                .createdUserDate(new Date())
//                .provider("form")
                .build();
    }
}
