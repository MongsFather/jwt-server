package com.mongsfather.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import com.mongsfather.user.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
   @EntityGraph(attributePaths = "authorities")	//���������� ��÷ε���ȸ eager
   Optional<User> findOneWithAuthoritiesByUsername(String username); //���������� ���������� ���� ȣ�� jpa ������α���
}
