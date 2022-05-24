package com.mongsfather.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mongsfather.user.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long>{
	Optional<RefreshToken> findByKey(String key);
}
