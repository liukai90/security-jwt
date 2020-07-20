package com.lk.security.config;


import com.lk.security.entity.UserDetail;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

import static com.lk.security.config.SecurityConstant.JWT_EXPRIRE_PC;
import static com.lk.security.config.SecurityConstant.TOKEN_KEY.*;
import static com.lk.security.config.SecurityConstant.key;


/**
 * @description: jwt工具类
 * @author: zhangqinglong@acoinfo.com
 * @time: 2020/4/27 15:33
 */
@Slf4j
public class JWTUtil {

    /**
     * @description: 根据旧的token刷新token
     * @return:
     */
    public static void refreshJWT(Jws<Claims> oldClaims, HttpServletRequest request, HttpServletResponse response, Boolean isAdmin) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(ID.getValue(),
                oldClaims.getBody().get(ID.getValue()));
        claims.put(REAL_NAME.getValue(),
                oldClaims.getBody().get(REAL_NAME.getValue()));
        claims.put(LOGIN_NAME.getValue(),
                oldClaims.getBody().get(LOGIN_NAME.getValue()));
        claims.put(AUTHORITIES.getValue(),
                oldClaims.getBody().get(AUTHORITIES.getValue()));
        claims.put(USERNAME.getValue(),
                oldClaims.getBody().get(USERNAME.getValue()));
        claims.put(PHONE.getValue(),
                oldClaims.getBody().get(PHONE.getValue()));
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        String token = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPRIRE_PC * 1000L))
                .signWith(key, signatureAlgorithm)
                .compact();

        Cookie cookie = null;
        if (isAdmin) {
            cookie = new Cookie(SecurityConstant.TOKEN_NAME.ADMIN_TOKEN.getValue(), token);
        } else {
            cookie = new Cookie(SecurityConstant.TOKEN_NAME.TOKEN.getValue(), token);
        }
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        setCookieDomain(request, cookie);
        response.addCookie(cookie);
    }


    /**
     * @description: 给token刷新新的权限进去
     * @return:
     */
    public static void refreshDeveloperJWT(HttpServletRequest request, HttpServletResponse response, String role) {
        Cookie[] cookies = request.getCookies();
        String token = "";
        if (cookies != null) {
            Optional<Cookie> tokenOptional = Arrays.stream(cookies).filter(x -> SecurityConstant.TOKEN_NAME.TOKEN.getValue().equals(x.getName())).findAny();
            if (tokenOptional.isPresent()) {
                token = tokenOptional.get().getValue();
            }
        }
        Jws<Claims> oldClaims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);

        ArrayList<GrantedAuthority> authList = (ArrayList) oldClaims.getBody()
                .get(AUTHORITIES.getValue());

        authList.add(new SimpleGrantedAuthority(role));


        Map<String, Object> claims = new HashMap<>();
        claims.put(ID.getValue(),
                oldClaims.getBody().get(ID.getValue()));
        claims.put(REAL_NAME.getValue(),
                oldClaims.getBody().get(REAL_NAME.getValue()));
        claims.put(LOGIN_NAME.getValue(),
                oldClaims.getBody().get(LOGIN_NAME.getValue()));
        claims.put(USERNAME.getValue(),
                oldClaims.getBody().get(USERNAME.getValue()));
        claims.put(AUTHORITIES.getValue(), authList);
        claims.put(PHONE.getValue(),
                oldClaims.getBody().get(PHONE.getValue()));
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        String newToken = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPRIRE_PC * 1000L))
                .signWith(key, signatureAlgorithm)
                .compact();
        Cookie cookie = new Cookie(SecurityConstant.TOKEN_NAME.TOKEN.getValue(), newToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        setCookieDomain(request, cookie);
        response.addCookie(cookie);
    }

    /**
     * @description: 把用户信息写入cookie
     * @return:
     */
    public static String writeUserInCookie(UserDetail user, HttpServletRequest request, HttpServletResponse response, String tokenName) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        Map<String, Object> claims = new HashMap<>();
        claims.put(ID.getValue(), user.getId());
        claims.put(REAL_NAME.getValue(), user.getRealName());
        claims.put(USERNAME.getValue(), user.getUsername());
        claims.put(LOGIN_NAME.getValue(), user.getLoginName());
        claims.put(AUTHORITIES.getValue(), user.getAuthorities() == null ? new ArrayList<GrantedAuthority>() : user.getAuthorities());
        String token;

        token = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPRIRE_PC * 1000L))
                .signWith(key, signatureAlgorithm)
                .compact();
        Cookie cookie = new Cookie(tokenName, token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        setCookieDomain(request, cookie);
        response.addCookie(cookie);
        return token;
    }


    /**
     * @description: 删除cookie
     * @return:
     */
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String tokenName) {
        Cookie cookie = new Cookie(tokenName, null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        setCookieDomain(request, cookie);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    /**
     * @param request
     * @param cookie
     * @description: 处理cookie的domian
     * 如果是以域名形式进来的，则设置cookie的domain为一级域名。保证cookie所有一级域名下可用，单点登录
     * @return:
     */
    private static void setCookieDomain(HttpServletRequest request, Cookie cookie) {
//        String domainName = request.getHeader(EdgerorCommonConstant.REQUEST_HEADER_DOMAIN_NAME);
//        //获取doaminName,并且domainName 不是ip
//        if (StringUtils.isNotBlank(domainName) && !IPAddress.isValid(domainName)) {
//            String[] domainStr = domainName.split("\\.");
//            if (domainStr != null && domainStr.length > 2) {
//                cookie.setDomain(domainStr[domainStr.length - 2] + "." + domainStr[domainStr.length - 1]);
//            }
//        }
    }

    /**
     * @description: 校验token, 并刷新token过期时间
     * @return:
     */
    public static Jws<Claims> validateToken(String token, HttpServletRequest request, HttpServletResponse response, Boolean isAdmin) throws Exception {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            Date expiration = claimsJws.getBody().getExpiration();
            //检查是否token快过期了，是的话刷新token的过期时间。
//            LocalDateTime localDate = DateUtils.asLocalDateTime(expiration);

//            if (Duration.between(LocalDateTime.now(), localDate).getSeconds() < SecurityConstant.RESIGN_TIME) {
//                JWTUtil.refreshJWT(claimsJws, request, response, isAdmin);
//            }
            return claimsJws;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.error("Invalid JWT signature.", e);
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token.", e);
            //throw new BadCredentialsException("登录已过期，请重新登录");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT token compact of handler are invalid.", e);
        }
        return null;
    }


}
