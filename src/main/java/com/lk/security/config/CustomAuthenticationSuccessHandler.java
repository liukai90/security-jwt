package com.lk.security.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.lk.security.dto.Response;
import com.lk.security.entity.UserDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author : liukai@acoinfo.com
 * @date : 2020-05-09 13:22
 * @description:
 */
@Slf4j
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    ObjectMapper objectMapper;



    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        UserDetail userDetail = (UserDetail)authentication.getPrincipal();
        String token = JWTUtil.writeUserInCookie(userDetail, request, response, "token");
        Map<String,String> data = new HashMap<>();
        data.put("token",token);
        log.info(userDetail.getUsername()+"成功登录！");
        //返回结果
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        PrintWriter writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(Response.SUCCESS("登陆成功！")));
        writer.close();

    }

}
