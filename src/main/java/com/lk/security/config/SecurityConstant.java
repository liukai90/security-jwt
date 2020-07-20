package com.lk.security.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;

/**
 * @description:
 * @author: zhangqinglong@acoinfo.cn
 * @time: 2020/3/17 19:27
 */
public final class SecurityConstant {
    public static final String SUCCESS = "success";

    /** 手机验证码登录url**/
    public static final String DEFAULT_LOGIN_PROCESSING_URL_MOBILE = "/login/mobile";
    /** 手机验证码 手机号参数名称 **/
    public static final String DEFAULT_PARAMETER_NAME_MOBILE = "phone";
    /** 手机验证码 验证码参数名称**/
    public static final String DEFAULT_PARAMETER_NAME_CODE = "verificationCode";

    /**
     * @description: token的key
     * @return:
     */
    public  static   enum TOKEN_KEY {
        ID("id"),
        REAL_NAME("real_name"),
        USERNAME("username"),
        LOGIN_NAME("login_name"),
        AUTHORITIES("auth"),
        PHONE("phone");


        private TOKEN_KEY(String value) {
            this.value = value;
        }
        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    };

    /** pc端过期时间 单位秒 **/
    public static final  int JWT_EXPRIRE_PC = 3*3600;

    /** app端过期时间 单位天 **/
    public static final  int JWT_EXPRIRE_APP = 3 * 12 * 30;

    /** 过期前重新签发token时间，也就是说token过期前多少秒内有访问的话，会重新签发token，进行续期 单位秒 **/
    public static final  int RESIGN_TIME = 1800;

    /** 必须使用最少88位的Base64对该令牌进行编码 */
    public static final  String JWT_BASE_64_SECRET = "d2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYKd2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYKd2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYKd2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYKd2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYKd2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYKd2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYKd2F0Y2ggLW4gMC4yIC4vcnVuLnNoICYK";

    /** Request Headers ： Authorization */
    public static final  String JWT_HEADER = "Authorization";

    /** 令牌前缀，最后留个空格 Bearer */
    public static final  String JWT_TOKEN_START_WITH = "Bearer ";

    /** 登录锁定时长 单位秒 */
    public static final int USER_LOGIN_LOCK_TIME = 5*60;

    /** 登录锁定次数 */
    public static final int USER_LOGIN_LOCK_ERROR_TIMES = 3;

    public static Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SecurityConstant.JWT_BASE_64_SECRET)) ;

    /**
     * 翼辉id的token名称用token
     * 运维项目的token用admin_token
     * */
    public  enum TOKEN_NAME{
        ADMIN_TOKEN("admin_token"),
        TOKEN("token");
        TOKEN_NAME(String value) {
            this.value = value;
        }
        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

}
