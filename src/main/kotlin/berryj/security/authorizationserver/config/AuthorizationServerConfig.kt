package berryj.security.authorizationserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.util.*


/**
 * Spring Authorization Server Config
 * @see <a href="https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html">spring-authorization-server</a>
 * @see https://www.appsdeveloperblog.com/spring-authorization-server-tutorial/
 */
@Configuration
class AuthorizationServerConfig {
    /**
     * Spring Security filter chain for the Protocol Endpoints.
     * @see: <a href="https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html">protocol-endpoints</a>
     */
    private fun createOAuth2AuthorizationServerConfigurer(): OAuth2AuthorizationServerConfigurer {
        return OAuth2AuthorizationServerConfigurer()
    }

    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java).oidc(Customizer.withDefaults())
        return http.formLogin(Customizer.withDefaults()).build();
        http.exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity> ->
            exceptions
                .defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/login"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        }
        return http.build()
    }

    @Bean
    @Order(2)
    // A Spring Security filter chain for authentication.
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests { authorizeRequests -> authorizeRequests.anyRequest().authenticated() }
            .formLogin(Customizer.withDefaults())

        return http.build()
    }

    @Bean
    // 	An instance of AuthorizationServerSettings to configure Spring Authorization Server.
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder()
            .build()
    }
}