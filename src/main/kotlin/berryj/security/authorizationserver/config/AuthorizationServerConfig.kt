package berryj.security.authorizationserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


/**
 * Spring Authorization Server Config
 * @see <a href="https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html">spring-authorization-server</a>
 * @see https://www.appsdeveloperblog.com/spring-authorization-server-tutorial/
 */
@Configuration
@EnableWebSecurity
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
//
        http.exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity> ->
            exceptions
                .defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/login"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        }
//        http.oauth2ResourceServer { resourceServer: OAuth2ResourceServerConfigurer<HttpSecurity> ->
//            resourceServer.jwt(Customizer.withDefaults())
//        }
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
    // 	An instance of UserDetailsService for retrieving users to authenticate.
    fun userDetailsService(): UserDetailsService {
        val encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
        val userDetails = User.withUsername("admin")
            .password(encoder.encode("password"))
            .roles("USER")
            .build()
        return InMemoryUserDetailsManager(userDetails)
    }



    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    // An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
    private fun generateRsaKey(): KeyPair {
        val keyPair: KeyPair = try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }
        return keyPair
    }

    @Bean
    // An instance of JwtDecoder for decoding signed access tokens.
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    // 	An instance of AuthorizationServerSettings to configure Spring Authorization Server.
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder()
            .build()
    }

    @Bean
    fun clientSettings(): ClientSettings? {
        return ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .requireProofKey(false)
            .build()
    }
}