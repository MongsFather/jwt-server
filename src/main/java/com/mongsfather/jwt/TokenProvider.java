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


   public TokenProvider(	//bean 생성 후 jwt token 의존성주입 함수
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds,
      @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidityInSeconds) {
      this.secret = secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;		//토큰만료시간 변수에 할당 30분 (1800초)
      this.refreshTokenValidityInMilliseconds = refreshTokenValidityInSeconds * 1000;		//토큰만료시간 변수에 할당 30분 (1800초)
   }

   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(secret);			//application.yml secret 키가 base64인코딩되어 있기때문에 디코딩필요 
      this.key = Keys.hmacShaKeyFor(keyBytes);					//디코딩 완료 후 키값 할당
   }

   // 권한정보 할당
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
    	         .setExpiration(validity)		//토큰만료시간 셋팅
    	         .compact();
      
      String refreshToken = Jwts.builder()
 	         .signWith(key, SignatureAlgorithm.HS512)
 	         .setExpiration(refreshValidity)
 	         .compact();
      
      return TokenDto.builder()
    		  .token(jwtToken)
    		  .refreshToken(refreshToken)
    		  .tokenExpireTime(validity.getTime())
    		  .build();
   }

   // 토큰을 파라미터로 전달받아 권한정보를 획득 후 User객체생성
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

      return new UsernamePasswordAuthenticationToken(principal, token, authorities); //User객체, 토큰, 권한정보를 받아 Authentication 객체 리턴
   }

   // 토큰유효성 검사 함수
   public boolean validateToken(String token) {
      try {
         Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         logger.info("잘못된 JWT 서명입니다.");
      } catch (ExpiredJwtException e) {
         logger.info("만료된 JWT 토큰입니다.");
      } catch (UnsupportedJwtException e) {
         logger.info("지원되지 않는 JWT 토큰입니다.");
      } catch (IllegalArgumentException e) {
         logger.info("JWT 토큰이 잘못되었습니다.");
      }
      return false;
   }
}
