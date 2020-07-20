package com.lk.security.config;

import com.lk.security.entity.UserDetail;
import com.lk.security.service.UserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author : liukai@acoinfo.com
 * @date : 2020-07-15 14:21
 * @description:
 */
@Configurable
@EnableWebSecurity
//开启 Spring Security 方法级安全注解 @EnableGlobalMethodSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailService userDetailService;

    @Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder() ;
    }

    @Bean
    public CustomUserAuthenticationFilter customUserAuthenticationFilter() throws Exception {
        CustomUserAuthenticationFilter customUserAuthenticationFilter = new CustomUserAuthenticationFilter();
        customUserAuthenticationFilter.setAuthenticationManager(authenticationManager());
        customUserAuthenticationFilter.setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler());
        customUserAuthenticationFilter.setAuthenticationFailureHandler(new CustomAuthenticationFailHandler());
        customUserAuthenticationFilter.setUsernameParameter("username");  // 登录用户名参数 默认为userName
        customUserAuthenticationFilter.setPasswordParameter("password"); // 登录密码参数 默认为password
        return customUserAuthenticationFilter;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 不拦截静态资源,所有用户均可访问的资源
        web.ignoring().antMatchers(
                "/webjars/**",
                "/swagger-resources/**",
                "/v2/**",
                "/assets/**",
                "/js/**",
                "/images/**",
                "/**/*.ico",
                "/**/*.js",
                "/**/*.css",
                "/*.html",
                "/**/*.html");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        		http.csrf().disable().
				formLogin().and().
				authorizeRequests().antMatchers(
						"/login"
				,"/actuator/**"
				,"/logout"
				,"/operations/registered"
				,"/operations/checks/mobile"
				,"/operations/checks/username"
				,"/password"
				,"/audithistory/ids").permitAll().
				anyRequest().authenticated().and().
				exceptionHandling().authenticationEntryPoint(customAuthenticationEntryPoint).accessDeniedHandler(customAccessDeniedHandler).and().
				logout().disable().
				sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
				addFilter(new JWTTokenFilter(authenticationManager(),"applicationName",customAuthenticationEntryPoint)).
				addFilterAt(customUserAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(this.userDetailService).passwordEncoder(passwordEncoder());
//        super.configure(auth);
    }
}
