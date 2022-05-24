package com.mongsfather.auth.service;

import java.util.Collections;

import javax.validation.Valid;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mongsfather.auth.dto.LoginDto;
import com.mongsfather.entity.Authority;
import com.mongsfather.entity.RefreshToken;
import com.mongsfather.entity.User;
import com.mongsfather.jwt.JwtFilter;
import com.mongsfather.jwt.TokenProvider;
import com.mongsfather.jwt.dto.TokenDto;
import com.mongsfather.repository.RefreshTokenRepository;
import com.mongsfather.repository.UserRepository;
import com.mongsfather.user.dto.UserDto;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManagerBuilder authenticationManagerBuilder;
	private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
	
	@Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) { //유저명으로 회원정보조회
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()	//권한생성
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()	//유저정보생성
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return userRepository.save(user);
    }
    
    @Transactional
    public TokenDto login(LoginDto loginDto) {
        // 1. Login ID/PW 를 기반으로 AuthenticationToken 생성
    	UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        // 2. 실제로 검증 (사용자 비밀번호 체크) 이 이루어지는 부분
        //    authenticate 메서드가 실행이 될 때 CustomUserDetailsService 에서 만들었던 loadUserByUsername 메서드가 실행됨        
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenDto tokenDto = tokenProvider.createToken(authentication);
        
        // 4. Request Header 에 token 셋팅
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + tokenDto.getToken());

        // 4. RefreshToken 생성
        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);
        
        // 5. refreshToken 셋팅
        tokenDto.setRefreshToken(refreshToken.getValue());
        
        return tokenDto;
    }

    @Transactional
    public TokenDto reissue(TokenDto tokenDto) {
        // 1. Refresh Token 검증
        if (!tokenProvider.validateToken(tokenDto.getRefreshToken())) {
            throw new RuntimeException("Refresh Token 이 유효하지 않습니다.");
        }

        // 2. Access Token 에서 User객체 가져오기
        Authentication authentication = tokenProvider.getAuthentication(tokenDto.getToken());

        // 3. 저장소에서 User 를 기반으로 Refresh Token 값 가져옴
        RefreshToken refreshToken = refreshTokenRepository.findByKey(authentication.getName())
                .orElseThrow(() -> new RuntimeException("로그아웃 된 사용자입니다."));

        // 4. Refresh Token 일치하는지 검사
        if (!refreshToken.getValue().equals(tokenDto.getRefreshToken())) {
            throw new RuntimeException("토큰의 유저 정보가 일치하지 않습니다.");
        }

        // 5. 새로운 토큰 생성
        TokenDto reissueTokenDto = tokenProvider.createToken(authentication);

        RefreshToken reissueRefreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(reissueTokenDto.getRefreshToken())
                .build();;
                
        // 6. 저장소 정보 업데이트
        refreshTokenRepository.save(reissueRefreshToken);

        // 토큰 발급
        return reissueTokenDto;
    }

}
