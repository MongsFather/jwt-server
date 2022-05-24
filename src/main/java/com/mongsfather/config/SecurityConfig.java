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
@EnableGlobalMethodSecurity(prePostEnabled = true)	//@PreAuthorize ������̼��� �޼ҵ������ �߰��ϱ����� ����
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    // Ŀ���� TokenProvider, JwtAuthenticationEntryPoint, JwtAccessDeniedHandler ����
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
    public PasswordEncoder passwordEncoder() { //Spring Security �����ӿ�ũ���� ��й�ȣ�� ��ȣȭ�Ҷ� ����Ҽ��ִ� �Լ��� ����
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
			.csrf().disable()		//��ū��� ���(stateless)���� ������ ���������� �������� �ʱ� ������ �ش� ��� ������ 
	        .exceptionHandling()
	        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
	        .accessDeniedHandler(jwtAccessDeniedHandler)
	
	        // enable h2-console
	        .and()
	        .headers()
	        .frameOptions()
	        .sameOrigin()
	
	        // ������ ������� �ʱ� ������ STATELESS�� ����
	        .and()
	        .sessionManagement()
	        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		
	        .and()
			.authorizeRequests()						//��縮����Ʈ������ �۹̼� ��
			.antMatchers(
						"/api/hello"					//�ش� request�� ���� ��� ���� ���
						,"/api/authenticate"			//��ū��û������ ��ū�˻�����
						,"/api/login"					//�α��ο����� ��ū�˻�����
						,"/api/signup"					//ȸ�����Կ����� ��ū�˻�����
			).permitAll()
			.anyRequest().authenticated()				//�׹��� request�� ���� �����ϰڴ� (ex �׹��� request�� 401 ���Ѿ��� response)
		
			.and()
	        .apply(new JwtSecurityConfig(tokenProvider));
	}	

}
