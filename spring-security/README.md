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

