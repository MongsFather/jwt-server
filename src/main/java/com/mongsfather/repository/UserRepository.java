package com.mongsfather.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import com.mongsfather.user.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
   @EntityGraph(attributePaths = "authorities")	//권한정보를 즉시로딩조회 eager
   Optional<User> findOneWithAuthoritiesByUsername(String username); //유저정보를 권한정보와 같이 호출 jpa 기능으로구현
}
