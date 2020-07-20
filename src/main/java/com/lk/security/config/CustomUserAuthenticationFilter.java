package com.lk.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * @author : liukai@acoinfo.com
 * @date : 2020-05-09 09:51
 * @description: 将登陆接口改为json传输
 */
@Slf4j
public class CustomUserAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    ObjectMapper mapper = new ObjectMapper();
    public CustomUserAuthenticationFilter(){

    }

    CustomUserAuthenticationFilter(AuthenticationManager authenticationManager,
                                   CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler,
                                   CustomAuthenticationFailHandler customAuthenticationFailHandler){
        CustomUserAuthenticationFilter userAuthenticationFilter = new CustomUserAuthenticationFilter();
        userAuthenticationFilter.setAuthenticationManager(authenticationManager);
        userAuthenticationFilter.setUsernameParameter("username");  // 登录用户名参数 默认为userName
        userAuthenticationFilter.setPasswordParameter("password"); // 登录密码参数 默认为password
        userAuthenticationFilter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler);//自定义成功登陆器
        userAuthenticationFilter.setAuthenticationFailureHandler(customAuthenticationFailHandler);//自定义失败处理器
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if ( !"POST".equals(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            Map<String,String> map = mapper.readValue(request.getInputStream(), Map.class);
            String pass =map.get(this.getPasswordParameter());
            String username =map.get(this.getUsernameParameter());

            if (username == null) {
                username = "";
            }
            if (pass == null) {
                pass = "";
            }
            username = username.trim();
            request.setAttribute(this.getPasswordParameter(),pass);
            request.setAttribute(this.getUsernameParameter(),username);
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, pass);
            this.setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }

}
