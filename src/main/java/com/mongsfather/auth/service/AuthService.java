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

    @Transactional
    public TokenDto reissue(TokenDto tokenDto) {
        // 1. Refresh Token ����
        if (!tokenProvider.validateToken(tokenDto.getRefreshToken())) {
            throw new RuntimeException("Refresh Token �� ��ȿ���� �ʽ��ϴ�.");
        }

        // 2. Access Token ���� User��ü ��������
        Authentication authentication = tokenProvider.getAuthentication(tokenDto.getToken());

        // 3. ����ҿ��� User �� ������� Refresh Token �� ������
        RefreshToken refreshToken = refreshTokenRepository.findByKey(authentication.getName())
                .orElseThrow(() -> new RuntimeException("�α׾ƿ� �� ������Դϴ�."));

        // 4. Refresh Token ��ġ�ϴ��� �˻�
        if (!refreshToken.getValue().equals(tokenDto.getRefreshToken())) {
            throw new RuntimeException("��ū�� ���� ������ ��ġ���� �ʽ��ϴ�.");
        }

        // 5. ���ο� ��ū ����
        TokenDto reissueTokenDto = tokenProvider.createToken(authentication);

        RefreshToken reissueRefreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(reissueTokenDto.getRefreshToken())
                .build();;
                
        // 6. ����� ���� ������Ʈ
        refreshTokenRepository.save(reissueRefreshToken);

        // ��ū �߱�
        return reissueTokenDto;
    }

}
