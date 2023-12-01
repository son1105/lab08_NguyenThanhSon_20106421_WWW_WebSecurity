package vn.edu.iuh.fit.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    public void globalConfig(AuthenticationManagerBuilder auth, PasswordEncoder encoder, DataSource dataSource) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .withDefaultSchema()
                .withUser(User.withUsername("admin")
                        .password(encoder.encode("admin"))
                        .roles("ADMIN")
                        .build())
                .withUser(User.withUsername("son")
                        .password(encoder.encode("son"))
                        .roles("SON")
                        .build())
                .withUser(User.withUsername("phong")
                        .password(encoder.encode("phong"))
                        .roles("USER")
                        .build())
        ;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/home", "/index").permitAll()// không cần authenticate
                        .requestMatchers("/api/**").hasAnyRole("ADMIN", "USER", "SON") // phải có role admin / user / son
                        .requestMatchers(("/admin/**")).hasRole("ADMIN")// phải đăng nhập với role admin
                        .anyRequest().authenticated()// không cần đăng nhập
        );
        http.httpBasic(Customizer.withDefaults());// mặc định
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
