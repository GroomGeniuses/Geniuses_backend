package groom.geniuses.geniuses.jwt;

import groom.geniuses.geniuses.dao.user.MemberRole;
import org.springframework.security.core.userdetails.UserDetails;

public interface CustomUserDetails extends UserDetails {
    public String getPKId();
    public MemberRole getRole();
}