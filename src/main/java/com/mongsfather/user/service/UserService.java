package com.mongsfather.user.service;

import java.util.Collections;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mongsfather.repository.UserRepository;
import com.mongsfather.user.dto.UserDto;
import com.mongsfather.user.entity.Authority;
import com.mongsfather.user.entity.User;
import com.mongsfather.util.SecurityUtil;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

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

    @Transactional(readOnly = true)
    public User getUserWithAuthorities(String username) { 
        return userRepository.findOneWithAuthoritiesByUsername(username).orElse(null);
    }

    @Transactional(readOnly = true)
    public User getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername).orElse(null);
    }
}
