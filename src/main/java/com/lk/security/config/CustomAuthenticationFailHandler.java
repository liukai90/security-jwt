package com.lk.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lk.security.dto.Response;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author : liukai@acoinfo.com
 * @date : 2020-05-09 13:23
 * @description:
 */
@Slf4j
@Component
public class CustomAuthenticationFailHandler implements AuthenticationFailureHandler {

    @Autowired
    ObjectMapper objectMapper;


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException ae) throws IOException, ServletException {
        log.error(ae.getMessage(), ae);
        //返回结果
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        PrintWriter writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(Response.FAIL(ae.getMessage())));
        writer.close();
    }


}
