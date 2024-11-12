package groom.geniuses.geniuses.dao.user;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Member {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    @Column(name="member_id")
//    private Long id;

    @Id
    private String userId;
    private String password;
    private String userName;
    private String image;
    private String introduce;
//    private String email;
//    private Date createdUserDate;

    @Enumerated(EnumType.STRING)
    private MemberRole role;

    // provider : social login 종류 (google / kakao)
    private String provider;
    // providerId : social login 유저의 고유 ID
    private String providerId;
}
