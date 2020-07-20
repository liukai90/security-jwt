package com.lk.security.service;

import com.lk.security.entity.UserDetail;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * @author : liukai@acoinfo.com
 * @date : 2020-07-15 14:27
 * @description:
 */
@Service
public class UserDetailService  implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetail userDetail = new UserDetail();
        if (userDetail == null) {
            throw new InternalAuthenticationServiceException("用户名或密码不正确!");
        }

        //查询用户是否被锁定

        userDetail.setId(1L);
        userDetail.setUsername("username");
        userDetail.setRealName("realName");
        userDetail.setPassword("password");

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority("admin"));
        userDetail.setGrantedAuthorities(grantedAuthorities);

        return userDetail;
    }
}
