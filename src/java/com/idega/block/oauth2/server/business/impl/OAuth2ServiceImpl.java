/**
 * @(#)OAuth2Util.java    1.0.0 14:43:51
 *
 * Idega Software hf. Source Code Licence Agreement x
 *
 * This agreement, made this 10th of February 2006 by and between
 * Idega Software hf., a business formed and operating under laws
 * of Iceland, having its principal place of business in Reykjavik,
 * Iceland, hereinafter after referred to as "Manufacturer" and Agura
 * IT hereinafter referred to as "Licensee".
 * 1.  License Grant: Upon completion of this agreement, the source
 *     code that may be made available according to the documentation for
 *     a particular software product (Software) from Manufacturer
 *     (Source Code) shall be provided to Licensee, provided that
 *     (1) funds have been received for payment of the License for Software and
 *     (2) the appropriate License has been purchased as stated in the
 *     documentation for Software. As used in this License Agreement,
 *     Licensee shall also mean the individual using or installing
 *     the source code together with any individual or entity, including
 *     but not limited to your employer, on whose behalf you are acting
 *     in using or installing the Source Code. By completing this agreement,
 *     Licensee agrees to be bound by the terms and conditions of this Source
 *     Code License Agreement. This Source Code License Agreement shall
 *     be an extension of the Software License Agreement for the associated
 *     product. No additional amendment or modification shall be made
 *     to this Agreement except in writing signed by Licensee and
 *     Manufacturer. This Agreement is effective indefinitely and once
 *     completed, cannot be terminated. Manufacturer hereby grants to
 *     Licensee a non-transferable, worldwide license during the term of
 *     this Agreement to use the Source Code for the associated product
 *     purchased. In the event the Software License Agreement to the
 *     associated product is terminated; (1) Licensee's rights to use
 *     the Source Code are revoked and (2) Licensee shall destroy all
 *     copies of the Source Code including any Source Code used in
 *     Licensee's applications.
 * 2.  License Limitations
 *     2.1 Licensee may not resell, rent, lease or distribute the
 *         Source Code alone, it shall only be distributed as a
 *         compiled component of an application.
 *     2.2 Licensee shall protect and keep secure all Source Code
 *         provided by this this Source Code License Agreement.
 *         All Source Code provided by this Agreement that is used
 *         with an application that is distributed or accessible outside
 *         Licensee's organization (including use from the Internet),
 *         must be protected to the extent that it cannot be easily
 *         extracted or decompiled.
 *     2.3 The Licensee shall not resell, rent, lease or distribute
 *         the products created from the Source Code in any way that
 *         would compete with Idega Software.
 *     2.4 Manufacturer's copyright notices may not be removed from
 *         the Source Code.
 *     2.5 All modifications on the source code by Licencee must
 *         be submitted to or provided to Manufacturer.
 * 3.  Copyright: Manufacturer's source code is copyrighted and contains
 *     proprietary information. Licensee shall not distribute or
 *     reveal the Source Code to anyone other than the software
 *     developers of Licensee's organization. Licensee may be held
 *     legally responsible for any infringement of intellectual property
 *     rights that is caused or encouraged by Licensee's failure to abide
 *     by the terms of this Agreement. Licensee may make copies of the
 *     Source Code provided the copyright and trademark notices are
 *     reproduced in their entirety on the copy. Manufacturer reserves
 *     all rights not specifically granted to Licensee.
 *
 * 4.  Warranty & Risks: Although efforts have been made to assure that the
 *     Source Code is correct, reliable, date compliant, and technically
 *     accurate, the Source Code is licensed to Licensee as is and without
 *     warranties as to performance of merchantability, fitness for a
 *     particular purpose or use, or any other warranties whether
 *     expressed or implied. Licensee's organization and all users
 *     of the source code assume all risks when using it. The manufacturers,
 *     distributors and resellers of the Source Code shall not be liable
 *     for any consequential, incidental, punitive or special damages
 *     arising out of the use of or inability to use the source code or
 *     the provision of or failure to provide support services, even if we
 *     have been advised of the possibility of such damages. In any case,
 *     the entire liability under any provision of this agreement shall be
 *     limited to the greater of the amount actually paid by Licensee for the
 *     Software or 5.00 USD. No returns will be provided for the associated
 *     License that was purchased to become eligible to receive the Source
 *     Code after Licensee receives the source code.
 */
package com.idega.block.oauth2.server.business.impl;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;

import javax.ejb.FinderException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MediaType;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Scope;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import com.idega.block.login.bean.OAuthToken;
import com.idega.block.login.business.OAuth2Service;
import com.idega.core.accesscontrol.business.LoginBusinessBean;
import com.idega.core.accesscontrol.data.LoginTable;
import com.idega.core.accesscontrol.data.LoginTableHome;
import com.idega.core.accesscontrol.event.LoggedInUserCredentials;
import com.idega.core.business.DefaultSpringBean;
import com.idega.data.IDOLookup;
import com.idega.data.IDOLookupException;
import com.idega.presentation.IWContext;
import com.idega.servlet.filter.RequestResponseProvider;
import com.idega.user.dao.UserDAO;
import com.idega.util.CoreConstants;
import com.idega.util.CoreUtil;
import com.idega.util.ListUtil;
import com.idega.util.StringHandler;
import com.idega.util.StringUtil;
import com.idega.util.expression.ELUtil;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.client.urlconnection.HTTPSProperties;

/**
 * <p>
 * Static class for managing users of OAuth2
 * </p>
 * <p>
 * You can report about problems to: <a href="mailto:martynas@idega.is">Martynas
 * Stakė</a>
 * </p>
 *
 * @version 1.0.0 2015 spal. 30
 * @author <a href="mailto:martynas@idega.is">Martynas Stakė</a>
 */
@Service("oauth2Service")
@Scope(BeanDefinition.SCOPE_SINGLETON)
public class OAuth2ServiceImpl extends DefaultSpringBean
		implements OAuth2Service, ApplicationListener<LoggedInUserCredentials> {

	private LoginTableHome loginTableHome;

	@Autowired
	private UserDAO userDAO;

	private LoginBusinessBean loginBusinessBean;

	@Autowired(required = false)
	private TokenStore tokenStore;

	private LoginBusinessBean getLoginBusinessBean() {
		if (this.loginBusinessBean == null) {
			this.loginBusinessBean = LoginBusinessBean.getDefaultLoginBusinessBean();
		}

		return this.loginBusinessBean;
	}

	private TokenStore getTokenStore() {
		if (this.tokenStore == null) {
			ELUtil.getInstance().autowire(this);
		}

		return this.tokenStore;
	}

	private UserDAO getUserDAO() {
		if (this.userDAO == null) {
			ELUtil.getInstance().autowire(this);
		}

		return this.userDAO;
	}

	private LoginTableHome getLoginTableHome() {
		if (loginTableHome == null) {
			try {
				loginTableHome = (LoginTableHome) IDOLookup.getHome(LoginTable.class);
			} catch (IDOLookupException e) {
				getLogger().log(Level.WARNING, "Failed to get " + LoginTableHome.class.getName(), e);
			}
		}

		return loginTableHome;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see com.idega.core.business.OAuth2Service#getAuthenticatedUser()
	 */
	@Override
	public com.idega.user.data.bean.User getAuthenticatedUser() {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		if (securityContext == null) {
			throw new IllegalStateException("Failed to get " + SecurityContext.class);
		}

		Authentication authentication = securityContext.getAuthentication();
		if (authentication == null) {
			throw new IllegalStateException("Failed to get authentication info from security context");
		}

		Object rawPrincipal = authentication.getPrincipal();
		if (rawPrincipal == null) {
			throw new IllegalStateException("Failed to get user from security context");
		}

		String login = null;
		if (rawPrincipal instanceof User) {
			User principal = (User) authentication.getPrincipal();
			if (principal == null) {
				throw new IllegalStateException("Failed to get user from security context");
			}
			login = principal.getUsername();
		} else if (rawPrincipal instanceof String) {
			login = (String) rawPrincipal;
		} else {
			throw new IllegalStateException("Failed to get user from security context");
		}

		LoginTable loginTable = null;
		try {
			loginTable = getLoginTableHome().findByLogin(login);
		} catch (FinderException e) {
			throw new IllegalStateException("User by login name " + login + " was not found");
		}

		com.idega.user.data.bean.User user = getUserDAO().getUser(loginTable.getUserId());

		IWContext iwc = CoreUtil.getIWContext();
		if (iwc == null) {
			RequestResponseProvider requestProvider = null;
			try {
				requestProvider = ELUtil.getInstance().getBean(RequestResponseProvider.class);
				HttpServletRequest request = requestProvider.getRequest();
				iwc = new IWContext(request, requestProvider.getResponse(), request.getServletContext());
			} catch (Exception e) {
				throw new IllegalStateException("Failed to create context for user " + login);
			}
		}

		try {
			if (iwc.isLoggedOn()) {
				com.idega.user.data.bean.User loggedInUser = iwc.getLoggedInUser();
				if (loggedInUser != null && loggedInUser.getId().intValue() == user.getId().intValue()) {
					return user;
				}

				if (LoginBusinessBean.getLoginBusinessBean(iwc.getRequest()).logInAsAnotherUser(iwc, user)) {
					return user;
				}
			} else {
				HttpServletRequest request = iwc.getRequest();
				if (LoginBusinessBean.getLoginBusinessBean(request).logInUser(request, user)) {
					return user;
				}
			}
		} catch (Exception e) {
			throw new IllegalStateException("Unable to login in user " + user);
		}

		return null;
	}

	@Override
	public boolean logoutUser() {
		com.idega.user.data.bean.User user = getAuthenticatedUser();
		if (user != null) {
			SecurityContext securityContext = SecurityContextHolder.getContext();
			if (securityContext == null) {
				throw new IllegalStateException("User is not logged in!");
			}

			OAuth2Authentication authentication = (OAuth2Authentication) securityContext.getAuthentication();
			if (authentication == null) {
				throw new IllegalStateException("Failed to get authentication info from security context");
			}

			Object rawPrincipal = authentication.getPrincipal();
			if (rawPrincipal == null) {
				throw new IllegalStateException("Failed to get user from security context");
			}

			String login = null;
			if (rawPrincipal instanceof User) {
				User principal = (User) authentication.getPrincipal();
				if (principal == null) {
					throw new IllegalStateException("Failed to get user from security context");
				}
				login = principal.getUsername();
			} else if (rawPrincipal instanceof String) {
				login = (String) rawPrincipal;
			} else {
				throw new IllegalStateException("Failed to get user from security context");
			}

			String tokenValue = authentication.getOAuth2Request().getRequestParameters().get("access_token");

			Collection<OAuth2AccessToken> tokens = getTokenStore().findTokensByClientIdAndUserName(authentication.getOAuth2Request().getClientId(), login);
			if (!ListUtil.isEmpty(tokens)) {
				for (OAuth2AccessToken token : tokens) {
					boolean remove = false;

					if (StringUtil.isEmpty(tokenValue)) {
						remove = true;
					} else if (tokenValue.equals(token.getValue())) {
						remove = true;
					}

					if (remove) {
						getTokenStore().removeAccessToken(token);
					}
				}
			}

			return getLoginBusinessBean().logOutUser(CoreUtil.getIWContext());
		}

		return true;
	}

	private String getURL(String serverURL) {
		if (!serverURL.endsWith(CoreConstants.SLASH)) {
			serverURL = serverURL.concat(CoreConstants.SLASH);
		}

		String url = serverURL.concat("authentication/oauth/token");
		if (url.startsWith("https") && getSettings().getBoolean("oauth.switch_to_http", Boolean.FALSE)) {
			url = StringHandler.replace(url, "https:", "http:");
		}
		return url;
	}

	@Override
	public OAuthToken getToken(String serverURL, String clientId, String clientSecret, String username,
			String password) {
		if (StringUtil.isEmpty(serverURL)) {
			return null;
		}
		if (StringUtil.isEmpty(username)) {
			return null;
		}
		if (StringUtil.isEmpty(password)) {
			return null;
		}

		if (StringUtil.isEmpty(clientId)) {
			clientId = getApplicationProperty("oauth_default_client_id");
		}
		if (StringUtil.isEmpty(clientId)) {
			getLogger().warning("Client ID is unknown");
			return null;
		}
		if (StringUtil.isEmpty(clientSecret)) {
			clientSecret = getApplicationProperty("oauth_default_client_secret");
		}
		if (StringUtil.isEmpty(clientSecret)) {
			getLogger().warning("Client secret is unknown");
			return null;
		}

		OAuthToken token = null;
		WebResource webResource = null;
		try {
			username = URLDecoder.decode(username, CoreConstants.ENCODING_UTF8);
			password = URLDecoder.decode(password, CoreConstants.ENCODING_UTF8);

			String url = getURL(serverURL);
			Client client = getClient(url);
			webResource = client.resource(url);
			webResource = webResource.queryParam("grant_type", "password").queryParam("client_id", clientId)
					.queryParam("client_secret", clientSecret)
					.queryParam("username", URLEncoder.encode(username, CoreConstants.ENCODING_UTF8))
					.queryParam("password", URLEncoder.encode(password, CoreConstants.ENCODING_UTF8));
			WebResource.Builder builder = webResource.accept(MediaType.APPLICATION_JSON);
			token = builder.post(OAuthToken.class);
		} catch (Exception e) {
			getLogger().log(Level.WARNING,
					"Error logging in user with username: " + username + ". Web resource: " + webResource, e);
			return null;
		}

		if (token == null || StringUtil.isEmpty(token.getAccess_token())) {
			getLogger().warning(
					"Error getting authentication token for username " + username + ". Web resource: " + webResource);
			return null;
		}

		return token;
	}

	private boolean isAllowedToAcceptAllCertificates(String url) {
		return !StringUtil.isEmpty(url) && url.startsWith("https")
				&& getSettings().getBoolean("oauth.accept_all_cert", Boolean.FALSE);
	}

	private Client getClient(String url) {
		if (isAllowedToAcceptAllCertificates(url)) {
			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				@Override
				public void checkClientTrusted(X509Certificate[] certs, String authType) {
				}

				@Override
				public void checkServerTrusted(X509Certificate[] certs, String authType) {
				}
			} };

			// Install the all-trusting trust manager
			SSLContext sc = null;
			try {
				sc = SSLContext.getInstance("TLS");
				sc.init(null, trustAllCerts, new SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			} catch (Exception e) {
			}

			ClientConfig config = new DefaultClientConfig();
			config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES,
					new HTTPSProperties(new HostnameVerifier() {
						@Override
						public boolean verify(String s, SSLSession sslSession) {
							return true;
						}
					}, sc));
			Client client = Client.create(config);
			return client;
		} else {
			return new Client();
		}
	}

	@Override
	public void onApplicationEvent(LoggedInUserCredentials credentials) {
		if (credentials == null) {
			return;
		}

		if (!getSettings().getBoolean("oauth_auto_create_token", Boolean.FALSE)) {
			return;
		}

		String username = credentials.getUserName();
		OAuthToken token = getToken(credentials.getServerURL(), null, null, username, credentials.getPassword());
		if (token != null) {
			getCache().put(username, token);
		}
	}

	private Map<String, OAuthToken> getCache() {
		Map<String, OAuthToken> cache = getCache("oauth2AccessTokensForUserNames", 604800, 604800, Integer.MAX_VALUE,
				false);
		return cache;
	}

	@Override
	public OAuthToken getToken(String username) {
		if (StringUtil.isEmpty(username)) {
			return null;
		}

		return getCache().get(username);
	}
}
