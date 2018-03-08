package com.idega.block.oauth2.server.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ejb.FinderException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.idega.block.login.data.dao.PasswordTokenEntityDAO;
import com.idega.block.user.bean.UserCredentials;
import com.idega.block.user.data.dao.UserCredentialsDAO;
import com.idega.core.accesscontrol.business.LoginBusinessBean;
import com.idega.core.accesscontrol.business.LoginDBHandler;
import com.idega.core.accesscontrol.data.LoginTable;
import com.idega.core.accesscontrol.data.LoginTableHome;
import com.idega.data.IDOLookup;
import com.idega.data.IDOLookupException;
import com.idega.presentation.IWContext;
import com.idega.servlet.filter.RequestResponseProvider;
import com.idega.user.dao.UserDAO;
import com.idega.user.data.bean.User;
import com.idega.util.CoreUtil;
import com.idega.util.StringUtil;
import com.idega.util.expression.ELUtil;

@Component
public class InternalAuthenticationProvider implements AuthenticationProvider {

	private static final Logger LOGGER = Logger.getLogger(InternalAuthenticationProvider.class.getName());

	@Autowired
	private PasswordTokenEntityDAO passwordTokenEntityDAO;

	@Autowired
	private UserDAO userDao;

	@Autowired(required = false)
	private UserCredentialsDAO userCredentialsDAO = null;

	private UserCredentialsDAO getUserCredentialsDAO() {
		if (this.userCredentialsDAO == null) {
			try {
				ELUtil.getInstance().autowire(this);
			} catch (Exception e) {}
		}

		return this.userCredentialsDAO;
	}

	public UserDAO getUserDao() {
		if (userDao == null) {
			ELUtil.getInstance().autowire(this);
		}
		return userDao;
	}

	public void setUserDao(UserDAO userDao) {
		this.userDao = userDao;
	}

	private LoginTableHome loginTableHome;

	private LoginTableHome getLoginTableHome() {
		if (loginTableHome == null) {
			try {
				loginTableHome = (LoginTableHome) IDOLookup.getHome(LoginTable.class);
			} catch (IDOLookupException e) {
				LOGGER.log(Level.WARNING, "Failed to get " + LoginTableHome.class.getName(), e);
			}
		}

		return loginTableHome;
	}

	public com.idega.user.data.bean.User getAuthenticatedUser() {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		if (securityContext == null) {
			throw new IllegalStateException("Failed to get " + SecurityContext.class);
		}

		Authentication authentication = securityContext.getAuthentication();
		return getAuthenticatedUser(authentication);
	}

	private com.idega.user.data.bean.User getAuthenticatedUser(Authentication authentication) {
		if (authentication == null) {
			throw new IllegalStateException("Failed to get authentication info from security context");
		}

		Object rawPrincipal = authentication.getPrincipal();
		if (rawPrincipal == null) {
			throw new IllegalStateException("Failed to get user from security context");
		}

		String login = null;
		if (rawPrincipal instanceof org.springframework.security.core.userdetails.User) {
			org.springframework.security.core.userdetails.User principal = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
			if (principal == null) {
				throw new IllegalStateException("Failed to get user from security context");
			}
			login = principal.getUsername();
		} else if (rawPrincipal instanceof String) {
			login = (String) rawPrincipal;
		} else {
			throw new IllegalStateException("Failed to get user from security context: " + rawPrincipal);
		}

		LoginTable loginTable = null;
		try {
			loginTable = getLoginTableHome().findByLogin(login);
		} catch (FinderException e) {
			throw new IllegalStateException("User by login name " + login + " was not found");
		}

		com.idega.user.data.bean.User user = getUserDao().getUser(loginTable.getUserId());

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

	private Authentication getAuthentication(String username) {
		if (StringUtil.isEmpty(username)) {
			return null;
		}

		UserCredentialsDAO credentialsDAO = getUserCredentialsDAO();
		if (credentialsDAO == null) {
			return null;
		}

		UserCredentials credentials = credentialsDAO.getUserCredentials(username);
		if (credentials == null || StringUtil.isEmpty(credentials.getUsername()) || StringUtil.isEmpty(credentials.getPassword())) {
			return null;
		}

		return getAuthentication(credentials.getUsername(), credentials.getPassword());
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String providedLogin = authentication.getName();
		String token = null;
		Object request = authentication.getDetails();
		if (request instanceof Map) {
			Map<?, ?> details = (Map<?, ?>) request;
			token = (String) details.get("token");
		}
		if (token == null) {
			return getAuthentication(providedLogin);
		}

		User user = getAuthenticatedUser(authentication);
		if (user == null) {
			return null;
		}

		LoginTable loginTable = LoginDBHandler.getUserLogin(user.getId());
		return getAuthentication(loginTable, providedLogin);
	}

	public Authentication getAuthentication(LoginTable loginTable, String providedLogin) {
		if (loginTable == null) {
			return null;
		}

		String login = null;
		String password = null;

		login = loginTable.getUserLogin();
		if (login == null) {
			return null;
		}
		if (!login.equals(providedLogin)) {
			return null;
		}

		password = loginTable.getUserPasswordInClearText();
		if (password == null) {
			return null;
		}

		return getAuthentication(login, password);
	}

	private Authentication getAuthentication(String login, String password) {
		List<GrantedAuthority> grantedAuths = new ArrayList<>();
		grantedAuths.add(new SimpleGrantedAuthority("ROLE_APP"));
		org.springframework.security.core.userdetails.User loggedInUser = new org.springframework.security.core.userdetails.User(
				login,
				password,
				grantedAuths
		);
		Authentication auth = new UsernamePasswordAuthenticationToken(loggedInUser, password, grantedAuths);
		return auth;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

	public PasswordTokenEntityDAO getPasswordTokenEntityDAO() {
		if (passwordTokenEntityDAO == null) {
			ELUtil.getInstance().autowire(this);
		}
		return passwordTokenEntityDAO;
	}

	public void setPasswordTokenEntityDAO(PasswordTokenEntityDAO passwordTokenEntityDAO) {
		this.passwordTokenEntityDAO = passwordTokenEntityDAO;
	}

}