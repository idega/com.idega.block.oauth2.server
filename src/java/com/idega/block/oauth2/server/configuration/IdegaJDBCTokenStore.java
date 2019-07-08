/**
 * @(#)IdegaJDBCTokenStore.java    1.0.0 16:30:15
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
package com.idega.block.oauth2.server.configuration;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import com.idega.util.StringUtil;

/**
 * <p>Workaround for https://github.com/spring-projects/spring-security-oauth/issues/754</p>
 * @version 1.0.0 2016-12-19
 * @author <a href="mailto:martynas@idega.is">Martynas Stakė</a>
 */
public class IdegaJDBCTokenStore extends JdbcTokenStore {

	private static final Logger LOGGER = Logger.getLogger(IdegaJDBCTokenStore.class.getName());

	public static final String ACCESS_TOKEN_INSERT_STATEMENT = "replace into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?)";
	public static final String REFRESH_TOKEN_INSERT_STATEMENT = "replace into oauth_refresh_token (token_id, token, authentication) values (?, ?, ?)";

	private Map<String, OAuth2AccessToken> accessTokenCache = new HashMap<>();
	private Map<String, OAuth2RefreshToken> refreshTokenCache = new HashMap<>();
	private Map<String, OAuth2Authentication> authenticationCache = new HashMap<>();
	private Map<String, OAuth2Authentication> authenticationCacheForRefresh = new HashMap<>();

	public IdegaJDBCTokenStore(DataSource dataSource) {
		super(dataSource);
		setInsertAccessTokenSql(ACCESS_TOKEN_INSERT_STATEMENT);
		setInsertRefreshTokenSql(REFRESH_TOKEN_INSERT_STATEMENT);
	}

	private Map<String, OAuth2AccessToken> getAccessTokenCache() {
		return accessTokenCache;
	}

	private Map<String, OAuth2RefreshToken> getRefreshTokenCache() {
		return refreshTokenCache;
	}

	private Map<String, OAuth2Authentication> getAuthenticationCache(boolean refresh) {
		return refresh ? authenticationCacheForRefresh : authenticationCache;
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		if (StringUtil.isEmpty(tokenValue)) {
			return null;
		}

		Map<String, OAuth2AccessToken> cache = getAccessTokenCache();
		OAuth2AccessToken cached = cache == null ? null : cache.get(tokenValue);
		if (cached != null) {
			return cached;
		}

		OAuth2AccessToken accessToken = super.readAccessToken(tokenValue);
		if (accessToken != null && cache != null) {
			cache.put(tokenValue, accessToken);
		}

		return accessToken;
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String token) {
		if (StringUtil.isEmpty(token)) {
			return null;
		}

		Map<String, OAuth2RefreshToken> cache = getRefreshTokenCache();
		OAuth2RefreshToken cached = cache == null ? null : cache.get(token);
		if (cached != null) {
			return cached;
		}

		OAuth2RefreshToken refreshToken = super.readRefreshToken(token);
		if (refreshToken != null && cache != null) {
			cache.put(token, refreshToken);
		}

		return refreshToken;
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		if (StringUtil.isEmpty(token)) {
			return null;
		}

		Map<String, OAuth2Authentication> cache = getAuthenticationCache(false);
		OAuth2Authentication cached = cache == null ? null : cache.get(token);
		if (cached != null) {
			return cached;
		}

		OAuth2Authentication authentication = super.readAuthentication(token);
		if (authentication != null && cache != null) {
			cache.put(token, authentication);
		}

		return authentication;
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
		if (StringUtil.isEmpty(value)) {
			return null;
		}

		Map<String, OAuth2Authentication> cache = getAuthenticationCache(true);
		OAuth2Authentication cached = cache == null ? null : cache.get(value);
		if (cached != null) {
			return cached;
		}

		OAuth2Authentication authentication = super.readAuthenticationForRefreshToken(value);
		if (authentication != null && cache != null) {
			cache.put(value, authentication);
		}

		return authentication;
	}

	private void updateRefreshCaches(String tokenId, OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		if (refreshToken == null) {
			return;
		}

		String refreshTokenId = refreshToken.getValue();

		Map<String, OAuth2RefreshToken> refreshTokens = getRefreshTokenCache();
		if (refreshTokens != null) {
			if (!StringUtil.isEmpty(tokenId)) {
				refreshTokens.put(tokenId, refreshToken);
			}
			if (!StringUtil.isEmpty(refreshTokenId)) {
				refreshTokens.put(refreshTokenId, refreshToken);
			}
		}

		if (!StringUtil.isEmpty(refreshTokenId) && authentication != null) {
			Map<String, OAuth2Authentication> authenticationsForRefresh = getAuthenticationCache(true);
			if (authenticationsForRefresh != null) {
				authenticationsForRefresh.put(refreshTokenId, authentication);
			}
		}
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		boolean saved = Boolean.FALSE;
		do {
			try {
				super.storeAccessToken(token, authentication);
				saved = Boolean.TRUE;

				addAccessTokenToCache(token, authentication);
			} catch (DuplicateKeyException e) {
				LOGGER.log(
						Level.WARNING,
						"Failed to store access token (" + token.getValue() + ", refresh token: " + (token.getRefreshToken() == null ? "unknown" : token.getRefreshToken().getValue()) +
						") due to duplicated key error, trying one more time. Authentication: " + authentication,
						e
				);

				try {
					Thread.sleep(1000);
				} catch (InterruptedException ie) {}
			}
		} while (!saved);
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		boolean saved = Boolean.FALSE;
		do {
			try {
				super.storeRefreshToken(refreshToken, authentication);
				saved = Boolean.TRUE;

				updateRefreshCaches(null, refreshToken, authentication);
			} catch (Exception e) {
				LOGGER.log(Level.WARNING, "Failed to store refresh token (" + refreshToken.getValue() + "), trying one more time. Authentication: " + authentication, e);

				try {
					Thread.sleep(1000);
				} catch (InterruptedException ie) {}
			}
		} while (!saved);
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(String refreshToken) {
		try {
			getRefreshTokenCache().remove(refreshToken);
			super.removeAccessTokenUsingRefreshToken(refreshToken);
		} catch (Exception e) {
			LOGGER.log(Level.WARNING, "Error removing access token using refresh token " + refreshToken, e);
		}
	}

	@Override
	public void removeAccessToken(String tokenValue) {
		try {
			getAccessTokenCache().remove(tokenValue);
			super.removeAccessToken(tokenValue);
		} catch (Exception e) {
			LOGGER.log(Level.WARNING, "Error removing access token " + tokenValue, e);
		}
	}

	@Override
	public void removeRefreshToken(String token) {
		try {
			getRefreshTokenCache().remove(token);
			super.removeRefreshToken(token);
		} catch (Exception e) {
			LOGGER.log(Level.WARNING, "Error removing refresh token " + token, e);
		}
	}

	public void addAccessTokenToCache(OAuth2AccessToken token, OAuth2Authentication authentication) {
		if (token == null || token.isExpired()) {
			return;
		}

		String tokenId = token.getValue();
		if (!StringUtil.isEmpty(tokenId)) {
			Map<String, OAuth2AccessToken> accessTokens = getAccessTokenCache();
			if (accessTokens != null) {
				accessTokens.put(tokenId, token);
			}

			if (authentication != null) {
				Map<String, OAuth2Authentication> authentications = getAuthenticationCache(false);
				if (authentications != null) {
					authentications.put(tokenId, authentication);
				}
			}
		}

		OAuth2RefreshToken refreshToken = token.getRefreshToken();
		updateRefreshCaches(tokenId, refreshToken, authentication);
	}

	public void removeTokensFromCache(OAuth2AccessToken token) {
		if (token == null) {
			return;
		}

		String tokenId = token.getValue();
		if (!StringUtil.isEmpty(tokenId)) {
			Map<String, OAuth2AccessToken> accessTokens = getAccessTokenCache();
			if (accessTokens != null) {
				accessTokens.remove(tokenId);
			}

			Map<String, OAuth2Authentication> authentications = getAuthenticationCache(false);
			if (authentications != null) {
				authentications.remove(tokenId);
			}
		}

		OAuth2RefreshToken refreshToken = token.getRefreshToken();
		if (refreshToken != null) {
			String refreshTokenId = refreshToken.getValue();
			if (!StringUtil.isEmpty(refreshTokenId)) {
				Map<String, OAuth2RefreshToken> refreshTokens = getRefreshTokenCache();
				if (refreshTokens != null) {
					refreshTokens.remove(refreshTokenId);
				}

				Map<String, OAuth2Authentication> authentications = getAuthenticationCache(true);
				if (authentications != null) {
					authentications.remove(refreshTokenId);
				}
			}
		}
	}

}