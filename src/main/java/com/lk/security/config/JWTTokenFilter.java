package com.lk.security.config;

import com.lk.security.entity.UserDetail;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Optional;


/**
 * @author perye
 * @email peryedev@gmail.com
 * @date 2019/12/13
 */
@Slf4j
public class JWTTokenFilter extends BasicAuthenticationFilter {

    /*
     ** 当前服务的名称
     */
    private String applicationName;

    // jwt过期处理
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    public JWTTokenFilter(AuthenticationManager authenticationManager, CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        super(authenticationManager);
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
    }

    public JWTTokenFilter(AuthenticationManager authenticationManager, String applicationName, CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        super(authenticationManager);
        this.applicationName = applicationName;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
    }

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
        String requestRri = request.getRequestURI();
        Cookie[] cookies = request.getCookies();
        String token = "";
        String authorization = request.getHeader("Authorization");
        Boolean isAdmin = false;
        //手机流程的token是存在header里面的Authorization 的
        if (StringUtils.hasText(authorization)) {
            token = authorization;
        } else if (cookies != null) {
            //Pc端的token是存在cookie里面的
            Optional<Cookie> tokenOpt = Optional.empty();
            if (!StringUtils.isEmpty(applicationName) && (
                    "edgeros-admin".equalsIgnoreCase(applicationName) ||
                            ("eap-store".equalsIgnoreCase(applicationName) &&
                                    requestRri.toLowerCase().startsWith("/eapadmin")))) {
                tokenOpt = Arrays.stream(cookies)
                        .filter(x -> SecurityConstant.TOKEN_NAME.ADMIN_TOKEN.getValue().equals(x.getName()))
                        .findFirst();
                isAdmin = true;
            } else {
                tokenOpt = Arrays.stream(cookies)
                        .filter(x -> SecurityConstant.TOKEN_NAME.TOKEN.getValue().equals(x.getName()))
                        .findFirst();
            }
            if (tokenOpt.isPresent()) {
                token = tokenOpt.get().getValue();
            }
        }
        if (StringUtils.hasText(token)) {
            Jws<Claims> claimsJws = JWTUtil.validateToken(token, request, response, isAdmin);

            if (claimsJws != null) {
                Authentication authentication = this.getAuthentication(claimsJws, token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("set Authentication to security context for '{}', uri: {}", authentication.getName(), requestRri);
            } else {
                log.debug("no valid JWT token found, uri: {}", requestRri);
            }
        } else {
            log.debug("no valid JWT token found, uri: {}", requestRri);
        }
        chain.doFilter(request, response);

    }

    /**
     * @param claims
     * @description: 从token中获取Authentication
     * @return:
     */
    private Authentication getAuthentication(Jws<Claims> claims, String token) {
        Claims body = claims.getBody();
        ArrayList<LinkedHashMap> authList = (ArrayList) body.get(SecurityConstant.TOKEN_KEY.AUTHORITIES.getValue());
        ArrayList<GrantedAuthority> list = new ArrayList<>();
        if (!CollectionUtils.isEmpty(authList)) {
            authList.stream().forEach(x -> {
                list.add(new SimpleGrantedAuthority((String) x.get("authority")));
            });
        }
        UserDetail userDetail = new UserDetail();
        userDetail.setId(Long.parseLong(body.get(SecurityConstant.TOKEN_KEY.ID.getValue()) + ""));
        userDetail.setUsername((String) body.get(SecurityConstant.TOKEN_KEY.USERNAME.getValue()));
        userDetail.setLoginName((String) body.get(SecurityConstant.TOKEN_KEY.LOGIN_NAME.getValue()));
        userDetail.setRealName((String) body.get(SecurityConstant.TOKEN_KEY.REAL_NAME.getValue()));
        userDetail.setGrantedAuthorities(list);
        return new UsernamePasswordAuthenticationToken(userDetail, token, list);
    }

}
