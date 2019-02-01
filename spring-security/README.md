## Setup
Spring Boot with Maven

    <dependencies>
        <!-- ... other dependency elements ... -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
    </dependencies>

Maven Without Spring Boot

    <dependencyManagement>
        <dependencies>
            <!-- ... other dependency elements ... -->
            <dependency>
                <groupId>org.springframework.security</groupId>
                <artifactId>spring-security-bom</artifactId>
                <version>5.1.3.RELEASE</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

BOM can be defined as above then the dependencies

    <dependencies>
    <!-- ... other dependency elements ... -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-config</artifactId>
        </dependency>
    </dependencies>
    
## Common Modules

### Core - spring-security-core.jar
Contains core authentication and access-contol classes and interfaces, remoting support and basic provisioning APIs. Required by any application which uses Spring Security. Supports standalone applications, remote clients, method (service layer) security and JDBC user provisioning.

### Web - spring-security-web.jar
Contains filters and related web-security infrastructure code. Anything with a servlet API dependency. You’ll need it if you require Spring Security web authentication services and URL-based access-control.

### Config - spring-security-config.jar
Contains the security namespace parsing code & Java configuration code. You need it if you are using the Spring Security XML namespace for configuration or Spring Security’s Java Configuration support. None of the classes are intended for direct use in an application.

### LDAP - spring-security-ldap.jar
LDAP authentication and provisioning code. Required if you need to use LDAP authentication or manage LDAP user entries.

### OAuth 2.0 Core - spring-security-oauth2-core.jar
spring-security-oauth2-core.jar contains core classes and interfaces that provide support for the OAuth 2.0 Authorization Framework and for OpenID Connect Core 1.0. It is required by applications that use OAuth 2.0 or OpenID Connect Core 1.0, such as Client, Resource Server, and Authorization Server.

### OAuth 2.0 Client - spring-security-oauth2-client.jar
spring-security-oauth2-client.jar is Spring Security’s client support for OAuth 2.0 Authorization Framework and OpenID Connect Core 1.0. Required by applications leveraging OAuth 2.0 Login and/or OAuth Client support.

### OAuth 2.0 JOSE - spring-security-oauth2-jose.jar
spring-security-oauth2-jose.jar contains Spring Security’s support for the JOSE (Javascript Object Signing and Encryption) framework. The JOSE framework is intended to provide a method to securely transfer claims between parties. It is built from a collection of specifications:
    • JSON Web Token (JWT)
    • JSON Web Signature (JWS)
    • JSON Web Encryption (JWE)
    • JSON Web Key (JWK)
      
### OpenID - spring-security-openid.jar
OpenID web authentication support. Used to authenticate users against an external OpenID server. Requires OpenID4Java.

## Configuration

### XML Configuration

security-config-xml

    <b:beans xmlns="http://www.springframework.org/schema/security"
            xmlns:b="http://www.springframework.org/schema/beans"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://www.springframework.org/schema/beans 						http://www.springframework.org/schema/beans/spring-beans.xsd
                    http://www.springframework.org/schema/security 					http://www.springframework.org/schema/security/spring-security.xsd">
           <http />
            <user-service>
                    <user name="user" password="password" authorities="ROLE_USER" />
            </user-service>
    </b:beans>

### Java Configuration

    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.context.annotation.*;
    import org.springframework.security.config.annotation.authentication.builders.*;
    import org.springframework.security.config.annotation.web.configuration.*;

    @EnableWebSecurity
    public class WebSecurityConfig implements WebMvcConfigurer {

    @Bean
    public UserDetailsService userDetailsService() throws Exception {
       InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
       manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").
       build());
       return manager;
    }
    }
    
The security-config-xml or equivalent Java Configuration  will:
    • Require authentication to every URL in your application
    • Generate a login form for you
    • Allow the user with the Username user and the Password password to authenticate with form based authentication
    • Allow the user to logout
    • CSRF attack prevention etc
The next step is to register the springSecurityFilterChain with the war.

This can be done in Java Configuration with Spring’s WebApplicationInitializer support in a Servlet 3.0+ environment.Spring Security provides a base class __AbstractSecurityWebApplicationInitializer__ that will ensure the springSecurityFilterChain gets registered for you. The way in which we use AbstractSecurityWebApplicationInitializer differs depending on if we are already using Spring or if Spring Security is the only Spring component in our application.

    
##### AbstractSecurityWebApplicationInitializer without Existing Spring

If you are not using Spring or Spring MVC, you will need to pass in the WebSecurityConfig into the superclass to ensure the configuration is picked up. You can find an example below:
import org.springframework.security.web.context.*;

    public class SecurityWebApplicationInitializer
        extends AbstractSecurityWebApplicationInitializer {

        public SecurityWebApplicationInitializer() {
            super(WebSecurityConfig.class);
        }
    }
    
The SecurityWebApplicationInitializer will do the following things:
    • Automatically register the springSecurityFilterChain Filter for every URL in your application
    • Add a ContextLoaderListener that loads the WebSecurityConfig.
      
##### AbstractSecurityWebApplicationInitializer with Spring MVC

If we were using Spring elsewhere in our application we probably already had a WebApplicationInitializer that is loading our Spring Configuration. If we use the previous configuration we would get an error. Instead, we should register Spring Security with the existing ApplicationContext. For example, if we were using Spring MVC our SecurityWebApplicationInitializer would look something like the following:

    import org.springframework.security.web.context.*;

    public class SecurityWebApplicationInitializer
        extends AbstractSecurityWebApplicationInitializer {

    }
    
This would simply only register the springSecurityFilterChain Filter for every URL in your application. After that we would ensure that WebSecurityConfig was loaded in our existing ApplicationInitializer. For example, if we were using Spring MVC it would be added in the getRootConfigClasses()

    public class MvcWebApplicationInitializer extends
            AbstractAnnotationConfigDispatcherServletInitializer {
        @Override
        protected Class<?>[] getRootConfigClasses() {
            return new Class[] { WebSecurityConfig.class };
        }
        // ... other overrides ...
    }

### XML Configuration

    <?xml version="1.0" encoding="UTF-8"?>
    <web-app version="3.0" xmlns="http://java.sun.com/xml/ns/javaee"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
      http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">

        <!--
          - Location of the XML file that defines the root application context
          - Applied by ContextLoaderListener.
          -->
        <context-param>
                <param-name>contextConfigLocation</param-name>
                <param-value>
                        /WEB-INF/spring/*.xml
                </param-value>
        </context-param>


        <filter>
                <filter-name>springSecurityFilterChain</filter-name>
                <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
        </filter>
        <filter-mapping>
                <filter-name>springSecurityFilterChain</filter-name>
                <url-pattern>/*</url-pattern>
        </filter-mapping>

        <!--
          - Loads the root application context of this web app at startup.
          - The application context is then available via
          - WebApplicationContextUtils.getWebApplicationContext(servletContext).
        -->
        <listener>
                <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
        </listener>

    </web-app>

The web.xml will do the following things:
    • Registers the springSecurityFilterChain Filter for every URL in your application
    • Adds a ContextLoaderListener that loads the security-config-xml.
    
## Core Concepts

### SecurityContextHolder, SecurityContext and Authentication Objects

The most fundamental object is SecurityContextHolder. This is where we store details of the present security context of the application, which includes details of the principal currently using the application. By default the SecurityContextHolder uses a ThreadLocal to store these details, which means that the security context is always available to methods in the same thread of execution, even if the security context is not explicitly passed around as an argument to those methods. Using a ThreadLocal in this way is quite safe if care is taken to clear the thread after the present principal’s request is processed. Of course, Spring Security takes care of this for you automatically so there is no need to worry about it.
Some applications aren’t entirely suitable for using a ThreadLocal, because of the specific way they work with threads. For example, a Swing client might want all threads in a Java Virtual Machine to use the same security context. SecurityContextHolder can be configured with a strategy on startup to specify how you would like the context to be stored. For a standalone application you would use the SecurityContextHolder.MODE_GLOBAL strategy. Other applications might want to have threads spawned by the secure thread also assume the same security identity. This is achieved by using SecurityContextHolder.MODE_INHERITABLETHREADLOCAL. You can change the mode from the default SecurityContextHolder.MODE_THREADLOCAL in two ways. The first is to set a system property, the second is to call a static method on SecurityContextHolder.

### Obtaining information about the current user

Inside the SecurityContextHolder we store details of the principal currently interacting with the application. Spring Security uses an Authentication object to represent this information. You won’t normally need to create an Authentication object yourself, but it is fairly common for users to query the Authenticationobject. You can use the following code block - from anywhere in your application - to obtain the name of the currently authenticated user, for example:

    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

    if (principal instanceof UserDetails) {
        String username = ((UserDetails)principal).getUsername();
    } else {
        String username = principal.toString();
    }
    
The object returned by the call to getContext() is an instance of the SecurityContext interface. This is the object that is kept in thread-local storage. As we’ll see below, most authentication mechanisms within Spring Security return an instance of UserDetails as the principal.


### The UserDetailsService
Another item to note from the above code fragment is that you can obtain a principal from the Authentication object. The principal is just an Object. Most of the time this can be cast into a UserDetails object. UserDetails is a core interface in Spring Security. It represents a principal, but in an extensible and application-specific way. Think of UserDetails as the adapter between your own user database and what Spring Security needs inside the SecurityContextHolder. Being a representation of something from your own user database, quite often you will cast the UserDetails to the original object that your application provided, so you can call business-specific methods (like getEmail(), getEmployeeNumber() and so on).
By now you’re probably wondering, so when do I provide a UserDetails object? How do I do that? I thought you said this thing was declarative and I didn’t need to write any Java code - what gives? The short answer is that there is a special interface called UserDetailsService. The only method on this interface accepts a String-based username argument and returns a UserDetails:

    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
    
This is the most common approach to loading information for a user within Spring Security and you will see it used throughout the framework whenever information on a user is required.
On successful authentication, UserDetails is used to build the Authentication object that is stored in the SecurityContextHolder (more on this below). The good news is that we provide a number of UserDetailsService implementations, including one that uses an in-memory map (InMemoryDaoImpl) and another that uses JDBC (JdbcDaoImpl). Most users tend to write their own, though, with their implementations often simply sitting on top of an existing Data Access Object (DAO) that represents their employees, customers, or other users of the application. Remember the advantage that whatever your UserDetailsService returns can always be obtained from the SecurityContextHolder

#### GrantedAuthority
Besides the principal, another important method provided by Authentication is getAuthorities(). This method provides an array of GrantedAuthorityobjects. A GrantedAuthority is, not surprisingly, an authority that is granted to the principal. Such authorities are usually "roles", such as ROLE_ADMINISTRATOR or ROLE_HR_SUPERVISOR. These roles are later on configured for web authorization, method authorization and domain object authorization. Other parts of Spring Security are capable of interpreting these authorities, and expect them to be present. GrantedAuthority objects are usually loaded by the UserDetailsService.
Usually the GrantedAuthority objects are application-wide permissions. They are not specific to a given domain object. Thus, you wouldn’t likely have a GrantedAuthority to represent a permission to Employee object number 54, because if there are thousands of such authorities you would quickly run out of memory (or, at the very least, cause the application to take a long time to authenticate a user). Of course, Spring Security is expressly designed to handle this common requirement, but you’d instead use the project’s domain object security capabilities for this purpose.

#### Summary
Just to recap, the major building blocks of Spring Security that we’ve seen so far are:<br />
    • SecurityContextHolder, to provide access to the SecurityContext.<br />
    • SecurityContext, to hold the Authentication and possibly request-specific security information.<br />
    • Authentication, to represent the principal in a Spring Security-specific manner.<br />
    • GrantedAuthority, to reflect the application-wide permissions granted to a principal.<br />
    • UserDetails, to provide the necessary information to build an Authentication object from your application’s DAOs or other source of security data.<br />
    • UserDetailsService, to create a UserDetails when passed in a String-based username (or certificate ID or the like).<br />

#### Authentication
What is authentication in Spring Security?
Let’s consider a standard authentication scenario that everyone is familiar with.<br />
    1.  A user is prompted to log in with a username and password.<br />
    2.  The system (successfully) verifies that the password is correct for the username.<br />
    3.  The context information for that user is obtained (their list of roles and so on).<br />
    4.  A security context is established for the user<br />
    5.  The user proceeds, potentially to perform some operation which is potentially protected by an access control mechanism which checks the required permissions for the operation against the current security context information.<br />
    
The first three items constitute the authentication process so we’ll take a look at how these take place within Spring Security.<br />
    1.  The username and password are obtained and combined into an instance of UsernamePasswordAuthenticationToken (an instance of the Authentication interface, which we saw earlier).<br />
    2.  The token is passed to an instance of AuthenticationManager for validation.<br />
    3.  The AuthenticationManager returns a fully populated Authentication instance on successful authentication.<br />
    4.  The security context is established by calling SecurityContextHolder.getContext().setAuthentication(..), passing in the returned authentication object.<br />
    
From that point on, the user is considered to be authenticated.<br />

Note that you don’t normally need to write any code like this. The process will normally occur internally, in a web authentication filter for example. We’ve just included the code here to show that the question of what actually constitutes authentication in Spring Security has quite a simple answer. A user is authenticated when the SecurityContextHolder contains a fully populated Authentication object.

#### Authentication in a Web Application
Now let’s explore the situation where you are using Spring Security in a web application (without web.xml security enabled). How is a user authenticated and the security context established?
Consider a typical web application’s authentication process:<br />
    1.  You visit the home page, and click on a link.<br />
    2.  A request goes to the server, and the server decides that you’ve asked for a protected resource.<br />
    3.  As you’re not presently authenticated, the server sends back a response indicating that you must authenticate. The response will either be an HTTP response code, or a redirect to a particular web page.<br />
    4.  Depending on the authentication mechanism, your browser will either redirect to the specific web page so that you can fill out the form, or the browser will somehow retrieve your identity (via a BASIC authentication dialogue box, a cookie, a X.509 certificate etc.).<br />
    5.  The browser will send back a response to the server. This will either be an HTTP POST containing the contents of the form that you filled out, or an HTTP header containing your authentication details.<br />
    6.  Next the server will decide whether or not the presented credentials are valid. If they’re valid, the next step will happen. If they’re invalid, usually your browser will be asked to try again (so you return to step two above).<br />
    7.  The original request that you made to cause the authentication process will be retried. Hopefully you’ve authenticated with sufficient granted authorities to access the protected resource. If you have sufficient access, the request will be successful. Otherwise, you’ll receive back an HTTP error code 403, which means "forbidden".<br />
    
Spring Security has distinct classes responsible for most of the steps described above. The main participants (in the order that they are used) are the ExceptionTranslationFilter, an AuthenticationEntryPoint and an "authentication mechanism", which is responsible for calling the AuthenticationManager

## Security Filter Chain

Authentication and Authorization process in Spring Security project are handled with filters technology. javax.servlet.Filter objects are standard part of Java Servlet API. They're objects which can be invoked on every request (independently on requested resource's type is static or dynamic)
They all have 3 methods: 
- init(FilterConfig config): called by servlet container after the filter is instantiated. This method is called only once and can be used, for example, to configure filter object with specified parameters. These parameters are retrieved from FilterConfig instance.
- doFilter(ServletRequest request, ServletResponse response, FilterChain chain): this is working method which makes some filtering operations on request and response objects. It's here for, for example, examine ServletRequest object and check if demanded resource is allowed to user making the request.
- destroy(): as the name indicates, this method is called when filter is taken out of service.

Filter are defined in web.xml descriptor file within org.springframework.security.web.FilterChainProxy. 
With it, we can simply define one filter in web.xml, as in below sample:

          <filter>
                <filter-name>springSecurityFilterChain</filter-name>
                <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
        </filter>
        <filter-mapping>
                <filter-name>springSecurityFilterChain</filter-name>
                <url-pattern>/*</url-pattern>
       </filter-mapping>
 
It may look strange that we are supposed to use FilterChainProxy but we are defining DelegatingFilterProxy in web.xml.
This object comes from Spring web project and helps to dispatch request catched by filter mapping to appropriate Spring bean. This strategy allows to take full advantage of Spring environment because filters invoked by servlet containers are Spring-managed beans and not detached objects, difficult to plug to Spring's application context. The name of bean to invoke is defined in targetBeanName parameter. If this parameter is absent, DelegatingFilterProxy uses filter name to find appropriate bean. As you can see in our example, bean used to execute security requests will be called springSecurityFilterChain and it corresponds to already mentioned FilterChainProxy.
FilterChainProxy extends org.springframework.web.filter.GenericFilterBean. Through this inheritance, it also implements javax.servlet.Filter interface, so it can be treated as standard filter with doFilter method implemented.

Note - FilterChainProxy can be configured and any custom filter can be added.

FilterChainProxy gets a list of filters, wrapps them into inner class VirtualFilterChain and executes through it.
The ‹http› namespace block always creates an __SecurityContextPersistenceFilter__, an __ExceptionTranslationFilter__ and a __FilterSecurityInterceptor__. These are fixed and cannot be replaced with alternatives. So by default when we add ‹http› element, the above three filters will be added. And if we  set auto-config to true, __BasicAuthenticationFilter__, __LogoutFilter__ and __UsernamePasswordAuthenticationFilter__ also gets added to the filter chain. Now if you look at the source code of any of these filters, these are also standard javax.servlet.Filter implementations. But by defining these filters in application context rather than in web.xml, the application server transfers the control to Spring to deal with security related tasks. And the Spring’s filterChainProxy will take care of chaining security filters that are to be applied on the request. This answers the third question.

Core Security Filters

# Access-Control (Authorization)

## Security and AOP Advice

In Spring AOP, there are different types of advice available: before, after, throws and around. An around advice is very useful, because an advisor can elect whether or not to proceed with a method invocation, whether or not to modify the response, and whether or not to throw an exception. Spring Security provides an around advice for method invocations as well as web requests. Around advice for method invocations can be achieved using Spring’s standard AOP support and for web requests using a standard Filter.

Most people are interested in securing method invocations on their services layer. This is because the services layer is where most business logic resides in current-generation Java EE applications. If you just need to secure method invocations in the services layer, Spring’s standard AOP will be adequate. If we need to secure domain objects directly, AspectJ is worth considering.

We can elect to perform __method authorization using AspectJ or Spring AOP__, or you can elect to perform __web request authorization using filters__. You can use zero, one, two or three of these approaches together. The mainstream usage pattern is to perform some web request authorization, coupled with some Spring AOP method invocation authorization on the services layer.

## Secure Objects

Spring Security uses the term "Secure Objects" to refer to any object that can have security (such as an authorization decision) applied to it. The most common examples are method invocations and web requests.

Each supported Secure Object type has its own interceptor class, which is a subclass of AbstractSecurityInterceptor.

For example -

1.  FilterSecurityInterceptor : Performs security handling of HTTP resources via a filter implementation.
2.  MethodSecurityInterceptor : Provides security interception of AOP Alliance based method invocations

Secure Object patterns is stored as SecurityMetadataSource in the form of ConfigAttribute.

## AbstractSecurityInterceptor

AbstractSecurityInterceptor provides a consistent workflow for handling secure object requests and by the time the it is called, the SecurityContextHolder will contain a valid Authentication if the principal has been authenticated.

AbstractSecurityInterceptor perform below steps once it is invoked by Spring, passing Object patterns as metadata

1.  Look up the "configuration attributes" associated with the present request
2.  Submitting the secure object, current Authentication and configuration attributes to the AccessDecisionManager for an       authorization decision
3.  Optionally change the Authentication under which the invocation takes place
4.  Allow the secure object invocation to proceed (assuming access was granted)
5.  Call the AfterInvocationManager if configured, once the invocation has returned. If the invocation raised an exception,     the AfterInvocationManager will not be invoked.

## AccessDecisionManager

The AccessDecisionManager is called by the AbstractSecurityInterceptor and is responsible for making final access control decisions. the AccessDecisionManager interface contains three methods

    void decide(Authentication authentication, Object secureObject, Collection<ConfigAttribute> attrs) throws AccessDeniedException;

    boolean supports(ConfigAttribute attribute);

    boolean supports(Class clazz);

The AccessDecisionManager's decide method is passed all the relevant information it needs in order to make an authorization decision. In particular, passing the secure Object enables those arguments contained in the actual secure object invocation to be inspected. For example, let’s assume the secure object was a MethodInvocation. It would be easy to query the MethodInvocation for any Customer argument, and then implement some sort of security logic in the AccessDecisionManager to ensure the principal is permitted to operate on that customer. Implementations are expected to throw an AccessDeniedException if access is denied.

The supports(ConfigAttribute) method is called by the AbstractSecurityInterceptor at startup time to determine if the AccessDecisionManager can process the passed ConfigAttribute. The supports(Class) method is called by a security interceptor implementation to ensure the configured AccessDecisionManager supports the type of secure object that the security interceptor will present.

## Voting-Based AccessDecisionManager Implementations

Whilst users can implement their own AccessDecisionManager to control all aspects of authorization, Spring Security includes several AccessDecisionManager implementations that are based on voting.

Using this approach, a series of AccessDecisionVoter implementations are polled on an authorization decision. The AccessDecisionManager then decides whether or not to throw an AccessDeniedException based on its assessment of the votes.

The AccessDecisionVoter interface has three methods:

    int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attrs);

    boolean supports(ConfigAttribute attribute);

    boolean supports(Class clazz);

Concrete implementations return an int, with possible values being reflected in the AccessDecisionVoter static fields ACCESS_ABSTAIN, ACCESS_DENIED and ACCESS_GRANTED. A voting implementation will return ACCESS_ABSTAIN if it has no opinion on an authorization decision. If it does have an opinion, it must return either ACCESS_DENIED or ACCESS_GRANTED.

There are three concrete AccessDecisionManagers provided with Spring Security that tally the votes. 

The __ConsensusBased__ implementation will grant or deny access based on the consensus of non-abstain votes. Properties are provided to control behavior in the event of an equality of votes or if all votes are abstain. 

The __AffirmativeBased__ implementation will grant access if one or more ACCESS_GRANTED votes were received (i.e. a deny vote will be ignored, provided there was at least one grant vote). Like the ConsensusBased implementation, there is a parameter that controls the behavior if all voters abstain. 

The __UnanimousBased__ provider expects unanimous ACCESS_GRANTED votes in order to grant access, ignoring abstains. It will deny access if there is any ACCESS_DENIED vote. Like the other implementations, there is a parameter that controls the behaviour if all voters abstain.

It is possible to implement a custom AccessDecisionManager that tallies votes differently. For example, votes from a particular AccessDecisionVoter might receive additional weighting, whilst a deny vote from a particular voter may have a veto effect.

## RoleVoter

The most commonly used AccessDecisionVoter provided with Spring Security is the simple RoleVoter, which treats configuration attributes as simple role names and votes to grant access if the user has been assigned that role.

It will vote if any ConfigAttribute begins with the prefix ROLE_. It will vote to grant access if there is a GrantedAuthority which returns a String representation (via the getAuthority() method) exactly equal to one or more ConfigAttributes starting with the prefix ROLE_. If there is no exact match of any ConfigAttribute starting with ROLE_, the RoleVoter will vote to deny access. If no ConfigAttribute begins with ROLE_, the voter will abstain.

## AuthenticatedVoter

Another voter which we’ve implicitly seen is the AuthenticatedVoter, which can be used to differentiate between anonymous, fully-authenticated and remember-me authenticated users. Many sites allow certain limited access under remember-me authentication, but require a user to confirm their identity by logging in for full access.

When we’ve used the attribute IS_AUTHENTICATED_ANONYMOUSLY to grant anonymous access, this attribute was being processed by the AuthenticatedVoter. See the Javadoc for this class for more information.

## Custom Voters

Obviously, you can also implement a custom AccessDecisionVoter and you can put just about any access-control logic you want in it. It might be specific to our application (business-logic related) or it might implement some security administration logic. 

## Summary

Spring passes all Secure Object patterns to be intercepted as metadata to AbstractSecurityInterceptor.AbstractSecurityInterceptor takes help of AccessDecisionManager for making final access control decisions.Spring provides three built-in access decision managers

1.  AffirmativeBased: At least one voter must vote to grant access
2.  ConsensusBased: Majority of voters must vote to grant access
3.  UnanimousBased: All voters must vote to abstain or grant access (no voter votes to deny access)

AccessDecisionManager is actually composed with one or multiple access decision voters. This voter encapsulates the logic to allow/deny/abstain the user from viewing the resource. Voting the decision as abstain is more or less similar to not voting at all.So the voting results are represented by the ACCESS_GRANTED, ACCESS_DENIED, and ACCESS_ABSTAIN constant fields defined in the AccessDecisionVoter interface. 

By default, an AffirmativeBased access decision manager is used with 2 voters: RoleVoter and AuthenticatedVoter. RoleVoter grants access if the user has some role as the resource required. But note that the role must start with “ROLE_” prefix if the voter has to grant access. But this can be customized for some other prefix as well. AuthenticatedVoter grants access only if user is authenticated. The authentication levels accepted are IS_AUTHENTICATED_FULLY, IS_AUTHENTICATED_REMEMBERED, and IS_AUTHENTICATED_ANONYMOUSLY. 

Below is an example of authorization through ‹intercept-url› in ‹http›


    <sec:http access-decision-manager-ref="accessDecisionManager">
      <sec:intercept-url pattern="/app/messageList*" access="ROLE_USER,ROLE_ANONYMOUS"/>
      <sec:intercept-url pattern="/app/messagePost*" access="ROLE_USER"/>
      <sec:intercept-url pattern="/app/messageDelete*" access="ROLE_ADMIN"/>
      <sec:intercept-url pattern="/app/*" access="ROLE_USER"/>

      <form-login login-page="/login.jsp" default-target-url="/app/messagePost"
        authentication-failure-url="/login.jsp?error=true"/>
      <!-- Other settings -->
    </sec:http>
    
Spring will pass all these urls to be intercepted as metadata to FilterSecurityInterceptor. So here is how the same can be configured without using ‹intercept-url›:
    
    <sec:custom-filter position="FILTER_SECURITY_INTERCEPTOR" ref="filterSecurityInterceptor" />
    <bean id="filterSecurityInterceptor" class="org.springframework.security.web.access.intercept.FilterSecurityInterceptor">
      <property name="authenticationManager" ref="authenticationManager"/>
      <property name="accessDecisionManager" ref="accessDecisionManager"/>
      <property name="securityMetadataSource">
      <sec:filter-security-metadata-source lowercase-comparisons="true" request-matcher="ant" use-expressions="true">
        <sec:intercept-url pattern="/app/messageList*" access="ROLE_USER,ROLE_ANONYMOUS"/>
        <sec:intercept-url pattern="/app/messagePost*" access="ROLE_USER"/>
        <sec:intercept-url pattern="/app/messageDelete*" access="ROLE_ADMIN"/>
        <sec:intercept-url pattern="/app/*" access="ROLE_USER"/>
      </sec:filter-security-metadata-source>
      </property>
    </bean>
    
Suppose we want to define a custom voter and add it to the access decision manager,

    <sec:http access-decision-manager-ref="accessDecisionManager" auto-config="true">
      <!-- filters declaration go here-->
    </sec:http>

    <bean id="accessDecisionManager" class="org.springframework.security.access.vote.AffirmativeBased">
      <property name="decisionVoters">
        <list>
          <bean class="org.springframework.security.access.vote.RoleVoter">
        <!-- Customize the prefix-->
        <property name="rolePrefix" value="ROLE_"/>
          </bean>
          <bean class="org.springframework.security.access.vote.AuthenticatedVoter"/>
          <bean class="<--custom voter with complete package-->"/>
        </list>
      </property>
    </bean>

