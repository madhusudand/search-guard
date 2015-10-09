/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.authentication.backend.keystone;

//import java.io.File;

import java.io.OutputStream;
//import java.net.ProtocolException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
//import com.floragunn.searchguard.authentication.LdapUser;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.NonCachingAuthenticationBackend;
//import com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator;
//import com.floragunn.searchguard.util.ConfigConstants;
//import com.floragunn.searchguard.util.SecurityUtil;
import com.floragunn.searchguard.util.ConfigConstants;

public class KeystoneAuthenticationBackend implements
		NonCachingAuthenticationBackend {

	protected final ESLogger log = Loggers.getLogger(this.getClass());
	private final Settings settings;

	@Inject
	public KeystoneAuthenticationBackend(final Settings settings) {
		this.settings = settings;
	}

	@Override
	public User authenticate(final AuthCredentials authCreds)
			throws AuthException {

		final String username = authCreds.getUsername();

		final char[] password = authCreds.getPassword();
		
		final String userpassword=new String(password);
		
        final String keystoneHost = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_KEYSTONE_HOST, null);
        
        final String keystonePort = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_KEYSTONE_PORT, null);
        
        final String userDomainName = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_KEYSTONE_DOMAIN_NAME,null);
        
        final String keystoneUrl = "https://"+keystoneHost+":"+keystonePort+"/v3/auth/tokens";


		int response_code;

		authCreds.clear();

		// ADDED BY MADHU FOR KEYSTONE INTEGRATION
		try {
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(new KeyManager[0],
					new TrustManager[] { new DefaultTrustManager() },
					new SecureRandom());
			SSLContext.setDefault(ctx);

			URL url = new URL(keystoneUrl);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setHostnameVerifier(new HostnameVerifier() {
				@Override
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			conn.setDoOutput(true);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Content-Type",
					"application/json; charset=UTF-8");

			String input = "{\"auth\": { \"identity\": { \"methods\": [ \"password\" ], \"password\": {\"user\": {  \"domain\": {\"name\": \""+userDomainName+"\" },\"name\": \""+username+"\", \"password\": \""+userpassword+"\" } } }}}";

			OutputStream os = conn.getOutputStream();
			os.write(input.getBytes());
			os.flush();

			response_code = conn.getResponseCode();
			conn.disconnect();
			if (response_code == 201) {
				log.debug("Authenticated username {}", username);

			} else {
				throw new AuthException("No user " + username
						+ " or wrong password");
			}
		} catch (Exception e) {

			log.error("exception during keystone authentication", e);
			throw new AuthException("No user " + username
					+ " or wrong password");

		}

		return new User(username);

		// log.debug("Authenticated username {}", username);

		// return new LdapUser(username, entry);

	}

	private static class DefaultTrustManager implements X509TrustManager {

		@Override
		public void checkClientTrusted(X509Certificate[] arg0, String arg1)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] arg0, String arg1)
				throws CertificateException {
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}

}
