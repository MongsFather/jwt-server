package com.mongsfather.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.mongsfather.jwt.JwtAccessDeniedHandler;
import com.mongsfather.jwt.JwtAuthenticationEntryPoint;
import com.mongsfather.jwt.JwtSecurityConfig;
import com.mongsfather.jwt.TokenProvider;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)	//@PreAuthorize 어노테이션을 메소드단위로 추가하기위해 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    // 커스텀 TokenProvider, JwtAuthenticationEntryPoint, JwtAccessDeniedHandler 주입
    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() { //Spring Security 프레임워크에서 비밀번호를 암호화할때 사용할수있는 함수를 제공
        return new BCryptPasswordEncoder();
    }
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		// TODO Auto-generated method stub
		web
			.ignoring()
			.antMatchers(
					"/h2-console/**"
					,"/favicon.ico"
			);
		
		super.configure(web);
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.csrf().disable()		//토큰방식 사용(stateless)으로 서버에 인증정보를 보관하지 않기 때문에 해당 기능 사용안함 
	        .exceptionHandling()
	        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
	        .accessDeniedHandler(jwtAccessDeniedHandler)
	
	        // enable h2-console
	        .and()
	        .headers()
	        .frameOptions()
	        .sameOrigin()
	
	        // 세션을 사용하지 않기 때문에 STATELESS로 설정
	        .and()
	        .sessionManagement()
	        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		
	        .and()
			.authorizeRequests()						//모든리퀘스트에대한 퍼미션 중
			.antMatchers(
						"/api/hello"					//해당 request에 대한 모든 권한 허용
						,"/api/authenticate"			//토큰요청에대한 토큰검사제외
						,"/api/login"					//로그인에대한 토큰검사제외
						,"/api/signup"					//회원가입에대한 토큰검사제외
			).permitAll()
			.anyRequest().authenticated()				//그밖의 request에 대한 검증하겠다 (ex 그밖의 request는 401 권한없음 response)
		
			.and()
	        .apply(new JwtSecurityConfig(tokenProvider));
	}	

}
