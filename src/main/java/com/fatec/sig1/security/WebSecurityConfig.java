
package com.fatec.sig1.security;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    // configuracao de autorizacao
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //http.authorizeRequests().antMatchers("/").hasAnyRole("ADMIN", "VEND", "OUTROS") //
        http.csrf().disable()
		.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/profissional").hasRole("ADMIN")
                .antMatchers("/sig/cliente", "/sig/cliente/**").hasAnyRole("ADMIN", "VEND")
				.antMatchers("/sig/clientes", "/sig/clientes/**").hasAnyRole("ADMIN", "VEND")
                .antMatchers("/sig/profissional", "/sig/profissional/**").hasAnyRole("ADMIN", "OUTROS")
				.antMatchers("/sig/profissionais", "/sig/profissionais/**").hasRole("ADMIN")
                .antMatchers("/sig/pedido", "/sig/pedido/**").hasAnyRole("ADMIN", "OUTROS")
				.antMatchers("/sig/pedidos", "/sig/pedidos/**").hasAnyRole("ADMIN", "OUTROS")
                .antMatchers("/sig/produto", "/sig/produto/**").hasAnyRole("ADMIN", "VEND", "OUTROS")
				.antMatchers("/sig/produtos", "/sig/produtos/**").hasAnyRole("ADMIN", "VEND")
                .antMatchers("/sig/servico", "/sig/servico/**").hasAnyRole("ADMIN", "VEND", "OUTROS")
				.antMatchers("/sig/servicos", "/sig/servicos/**").hasAnyRole("ADMIN", "OUTROS")
                .anyRequest().authenticated().and().formLogin().loginPage("/login").permitAll().and().logout()
                .logoutSuccessUrl("/login?logout").permitAll().and()
				.httpBasic();
    }
    // configuracao de autenticacao
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("jose").password(pc().encode("123")).roles("ADMIN").and()
            .withUser("maria").password(pc().encode("456")).roles("VEND").and()
            .withUser("fernanda").password(pc().encode("789")).roles("OUTROS");
    }
    @Bean
    public BCryptPasswordEncoder pc() {
        return new BCryptPasswordEncoder();
    }
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/static/**", "/css/**", "/js/**", "/images/**", "/h2-console/**");
    }
}
