package com.mongsfather.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import com.mongsfather.jwt.dto.TokenDto;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

   private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

   private static final String AUTHORITIES_KEY = "auth";

   private final String secret;
   private final long tokenValidityInMilliseconds;
   private final long refreshTokenValidityInMilliseconds;

   private Key key;


   public TokenProvider(	//bean ���� �� jwt token ���������� �Լ�
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds,
      @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidityInSeconds) {
      this.secret = secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;		//��ū����ð� ������ �Ҵ� 30�� (1800��)
      this.refreshTokenValidityInMilliseconds = refreshTokenValidityInSeconds * 1000;		//��ū����ð� ������ �Ҵ� 30�� (1800��)
   }

   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(secret);			//application.yml secret Ű�� base64���ڵ��Ǿ� �ֱ⶧���� ���ڵ��ʿ� 
      this.key = Keys.hmacShaKeyFor(keyBytes);					//���ڵ� �Ϸ� �� Ű�� �Ҵ�
   }

   // �������� �Ҵ�
   public TokenDto createToken(Authentication authentication) {
      String authorities = authentication.getAuthorities().stream()
         .map(GrantedAuthority::getAuthority)
         .collect(Collectors.joining(","));

      long now = (new Date()).getTime();
      Date validity = new Date(now + this.tokenValidityInMilliseconds);
      Date refreshValidity = new Date(now + this.refreshTokenValidityInMilliseconds);
      
      String jwtToken = Jwts.builder()
    	         .setSubject(authentication.getName())
    	         .claim(AUTHORITIES_KEY, authorities)
    	         .signWith(key, SignatureAlgorithm.HS512)
    	         .setExpiration(validity)		//��ū����ð� ����
    	         .compact();
      
      String refreshToken = Jwts.builder()
 	         .signWith(key, SignatureAlgorithm.HS512)
 	         .setExpiration(refreshValidity)
 	         .compact();
      
      return TokenDto.builder()
    		  .token(jwtToken)
    		  .refreshToken(refreshToken)
    		  .build();
   }

   // ��ū�� �Ķ���ͷ� ���޹޾� ���������� ȹ�� �� User��ü����
   public Authentication getAuthentication(String token) {
      Claims claims = Jwts
              .parserBuilder()
              .setSigningKey(key)
              .build()
              .parseClaimsJws(token)
              .getBody();

      Collection<? extends GrantedAuthority> authorities =
         Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

      User principal = new User(claims.getSubject(), "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities); //User��ü, ��ū, ���������� �޾� Authentication ��ü ����
   }

   // ��ū��ȿ�� �˻� �Լ�
   public boolean validateToken(String token) {
      try {
         Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         logger.info("�߸��� JWT �����Դϴ�.");
      } catch (ExpiredJwtException e) {
         logger.info("����� JWT ��ū�Դϴ�.");
      } catch (UnsupportedJwtException e) {
         logger.info("�������� �ʴ� JWT ��ū�Դϴ�.");
      } catch (IllegalArgumentException e) {
         logger.info("JWT ��ū�� �߸��Ǿ����ϴ�.");
      }
      return false;
   }
}
