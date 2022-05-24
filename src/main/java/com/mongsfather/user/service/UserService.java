package com.mongsfather.user.service;

import java.util.Collections;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mongsfather.jwt.JwtFilter;
import com.mongsfather.jwt.TokenProvider;
import com.mongsfather.jwt.dto.TokenDto;
import com.mongsfather.repository.RefreshTokenRepository;
import com.mongsfather.repository.UserRepository;
import com.mongsfather.user.dto.UserDto;
import com.mongsfather.user.entity.Authority;
import com.mongsfather.user.entity.RefreshToken;
import com.mongsfather.user.entity.User;
import com.mongsfather.user.login.dto.LoginDto;
import com.mongsfather.util.SecurityUtil;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) { //���������� ȸ��������ȸ
            throw new RuntimeException("�̹� ���ԵǾ� �ִ� �����Դϴ�.");
        }

        Authority authority = Authority.builder()	//���ѻ���
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()	//������������
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
        // 1. Login ID/PW �� ������� AuthenticationToken ����
    	UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        // 2. ������ ���� (����� ��й�ȣ üũ) �� �̷������ �κ�
        //    authenticate �޼��尡 ������ �� �� CustomUserDetailsService ���� ������� loadUserByUsername �޼��尡 �����        
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. ���� ������ ������� JWT ��ū ����
        TokenDto tokenDto = tokenProvider.createToken(authentication);
        
        // 4. Request Header �� token ����
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + tokenDto.getToken());

        // 4. RefreshToken ����
        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);
        
        // 5. refreshToken ����
        tokenDto.setRefreshToken(refreshToken.getValue());
        
        return tokenDto;
    }

    @Transactional(readOnly = true)
    public User getUserWithAuthorities(String username) { 
        return userRepository.findOneWithAuthoritiesByUsername(username).orElse(null);
    }

    @Transactional(readOnly = true)
    public User getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername).orElse(null);
    }
}
