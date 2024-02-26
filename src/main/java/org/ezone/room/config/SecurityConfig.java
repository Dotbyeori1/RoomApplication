package org.ezone.room.config;

import lombok.RequiredArgsConstructor;
import org.ezone.room.security.*;
import org.ezone.room.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig{

    // 로그인&시큐리티 관련
    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOauth2UserService customOauth2UserService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final TokenProvider tokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/member/logout"))
                        .logoutSuccessUrl("/"));

        http.oauth2Login(oauth2Login -> oauth2Login.redirectionEndpoint(redirectionEndpoint ->redirectionEndpoint.baseUri("/member/login/oauth2/code/**"))
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userService(customOauth2UserService))
                .successHandler(oAuth2AuthenticationSuccessHandler()));

        http.exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(customAuthenticationEntryPoint)); // 예외 발생시 어디로 리다이렉트 시키겠다

        http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)); //세션 유지 정책

        // 스프링 시큐리티 필터가 돌기전에 해야하는 것들
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        http.authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/admin","/admin/**").hasRole("ADMIN")
                                .requestMatchers("/seller/**").hasAnyRole("ADMIN", "SELLER")
                                .requestMatchers("/reservation/**").authenticated()
                                .requestMatchers("/product/**", "/","/page/**", "/review/**", "/member/**", "/member/login/oauth2/code/**", "/main", "/auth").permitAll()
                                .requestMatchers("/css/**", "/js/**", "/img/**", "/imgtest/**", "/assets/**", "/sbadmin/**", "/icon/**", "/**").permitAll()
                                .requestMatchers("/images/**", "/product/**").permitAll()
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .anyRequest().authenticated()); // 경로 설정 // antMatchers : 일반적인 경로 설정 // mvc : mvc 패턴의 경로 설정 (ex : /board/{id

        return http.build();
    }

    // 비밀번호 암호화 세팅
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(customUserDetailsService);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() { //CORS 설정
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("X-Requested-With", "Content-Type", "Authorization", "X-XSRF-token"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}