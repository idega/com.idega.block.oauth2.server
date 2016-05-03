/**
 * @(#)OAuth2DAOImpl.java    1.0.0 16:05:42
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
package com.idega.block.oauth2.server.data.dao.impl;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import com.idega.block.oauth2.server.data.dao.OAuth2DAO;
import com.idega.data.SimpleQuerier;
import com.idega.util.ListUtil;

/**
 * <p>You can report about problems to:
 * <a href="mailto:martynas@idega.is">Martynas Stakė</a></p>
 *
 * @version 1.0.0 2015 spal. 30
 * @author <a href="mailto:martynas@idega.is">Martynas Stakė</a>
 */
@Service
@Scope(BeanDefinition.SCOPE_SINGLETON)
public class OAuth2DAOImpl implements OAuth2DAO {

	private void execute(String query) {
		try {
			SimpleQuerier.executeUpdate(query, true);
		} catch (SQLException e) {
			java.util.logging.Logger.getLogger(getClass().getName()).log(
					Level.WARNING,
					"Failed to execute query '" + query +
					"' cause of: ", e);
		}
	}

	public void createOAuthClientDetailsTable() {
		StringBuilder query = new StringBuilder();
		query
		.append("CREATE TABLE oauth_client_details (")
		.append("    client_id VARCHAR(255) PRIMARY KEY,")
		.append("    resource_ids VARCHAR(256),")
		.append("    client_secret VARCHAR(256),")
		.append("    scope VARCHAR(256),")
		.append("    authorized_grant_types VARCHAR(256),")
		.append("    web_server_redirect_uri VARCHAR(256),")
		.append("    authorities VARCHAR(256),")
		.append("    access_token_validity INTEGER,")
		.append("    refresh_token_validity INTEGER,")
		.append("    additional_information VARCHAR(4000),")
		.append("    autoapprove VARCHAR(256)")
		.append(")");

		execute(query.toString());
	}

	public void createOAuthClientTokenTable() {
		StringBuilder query = new StringBuilder();
		query
		.append("CREATE TABLE oauth_client_token (")
		.append("    token_id VARCHAR(256),")
		.append("    token BLOB,")
		.append("    authentication_id VARCHAR(255) PRIMARY KEY,")
		.append("    user_name VARCHAR(256),")
		.append("    client_id VARCHAR(256)")
		.append(")");

		execute(query.toString());
	}

	public void createOAuthAccessTokenTable() {
		StringBuilder query = new StringBuilder();
		query
		.append("CREATE TABLE oauth_access_token (")
		.append("    token_id VARCHAR(256),")
		.append("    token BLOB,")
		.append("    authentication_id VARCHAR(255) PRIMARY KEY,")
		.append("    user_name VARCHAR(256),")
		.append("    client_id VARCHAR(256),")
		.append("    authentication BLOB,")
		.append("    refresh_token VARCHAR(256)")
		.append(")");

		execute(query.toString());
	}

	public void createOAuthRefreshTokenTable() {
		StringBuilder query = new StringBuilder();
		query
		.append("CREATE TABLE oauth_refresh_token (")
		.append("    token_id VARCHAR(256),")
		.append("    token BLOB,")
		.append("    authentication BLOB")
		.append(")");

		execute(query.toString());
	}

	public void createOAuthCodeTable() {
		StringBuilder query = new StringBuilder();
		query
		.append("CREATE TABLE oauth_code (")
		.append("    code VARCHAR(256),")
		.append("    authentication BLOB")
		.append(")");

		execute(query.toString());
	}

	public void createOAuthApprovalsTable() {
		StringBuilder query = new StringBuilder();
		query
		.append("CREATE TABLE oauth_approvals (")
		.append("    userId VARCHAR(256),")
		.append("    clientId VARCHAR(256),")
		.append("    scope VARCHAR(256),")
		.append("    status VARCHAR(10),")
		.append("    expiresAt TIMESTAMP,")
		.append("    lastModifiedAt TIMESTAMP")
		.append(")");

		execute(query.toString());
	}

	public void createClientDetailsTable() {
		StringBuilder query = new StringBuilder();
		query
		.append("CREATE TABLE ClientDetails (")
		.append("    appId VARCHAR(255) PRIMARY KEY,")
		.append("    resourceIds VARCHAR(256),")
		.append("    appSecret VARCHAR(256),")
		.append("    scope VARCHAR(256),")
		.append("    grantTypes VARCHAR(256),")
		.append("    redirectUrl VARCHAR(256),")
		.append("    authorities VARCHAR(256),")
		.append("    access_token_validity INTEGER,")
		.append("    refresh_token_validity INTEGER,")
		.append("    additionalInformation VARCHAR(4000),")
		.append("    autoApproveScopes VARCHAR(256)")
		.append(")");

		execute(query.toString());
	}

	/**
	 *
	 * @return names of existing tables with pattern oauth_*
	 */
	private List<String> getTableNames() {
		Connection connection = null;
		try {
			connection = SimpleQuerier.getConnection();
		} catch (SQLException e) {
			java.util.logging.Logger.getLogger(getClass().getName()).log(
					Level.WARNING,
					"Failed to get connection to database, cause of", e);
		}

		DatabaseMetaData meta = null;
		try {
			meta = connection.getMetaData();
		} catch (SQLException e) {
			java.util.logging.Logger.getLogger(getClass().getName()).log(
					Level.WARNING, ""
							+ "Failed to get database metadata, cause of:", e);
		}

		ResultSet resultSet = null;
		try {
			resultSet = meta.getTables(null, null, "%", null);
		} catch (SQLException e) {
			java.util.logging.Logger.getLogger(getClass().getName()).log(Level.WARNING,
					"Failed to get existing table names, cause of:", e);
		}

		ArrayList<String> tableNames = new ArrayList<String>();
		try {
			while (resultSet.next()) {
				tableNames.add(resultSet.getString("TABLE_NAME"));
			}
		} catch (SQLException e) {
			java.util.logging.Logger.getLogger(getClass().getName()).log(
					Level.WARNING,
					"Failed to get table names, cause of:", e);
		}

		return tableNames;
	}

	/* (non-Javadoc)
	 * @see com.idega.block.oauth2.server.data.dao.OAuth2DAO#createTables()
	 */
	@Override
	public void checkTables() {
		List<String> tableNames = getTableNames();
		if (!ListUtil.isEmpty(tableNames)) {
			if (!tableNames.contains("oauth_client_details")) {
				createClientDetailsTable();
				createOAuthClientDetailsTable();
			}

			if (!tableNames.contains("oauth_client_token")) {
				createOAuthClientTokenTable();
			}

			if (!tableNames.contains("oauth_access_token")) {
				createOAuthAccessTokenTable();
			}

			if (!tableNames.contains("oauth_refresh_token")) {
				createOAuthRefreshTokenTable();
			}

			if (!tableNames.contains("oauth_code")) {
				createOAuthCodeTable();
			}

			if (!tableNames.contains("oauth_approvals")) {
				createOAuthApprovalsTable();
			}
		}
	}
}
