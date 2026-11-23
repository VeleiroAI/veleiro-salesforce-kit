/**
 * Where the Veleiro API token lives after 1.9.0.
 *
 * Preferred store: the packaged External Credential principal (platform-encrypted).
 * Callouts then use Veleiro_API_Secure / Veleiro_API_Beta_Secure and Apex does not
 * attach an Authorization header.
 *
 * Reliable store: protected hierarchy custom setting Veleiro_Secret__c. Subscribers
 * cannot read it. The post-install script can write it, because that context cannot
 * make the ConnectApi callout that an External Credential needs.
 *
 * Fallback: the legacy public Veleiro_Config__c.Api_Token__c field, only when the
 * protected copy did not succeed. It is cleared after a successful copy. Callouts
 * that still use this token go only to the original packaged Named Credentials.
 *
 * Platform auth takes two transactions. A ConnectApi credential write leaves
 * uncommitted work, so the GET /clients probe cannot run after it in the same
 * transaction ("You have uncommitted work pending"). preparePlatformAuth() writes
 * the principal and records Platform_Write_Pending__c; confirmPlatformAuth() runs
 * later in its own transaction, calls out before any DML, and only then marks
 * Platform_Auth__c.
 */
public with sharing class VeleiroCredentialStore {

    public static final String EXTERNAL_CREDENTIAL = 'Veleiro_External';
    public static final String PRINCIPAL = 'VeleiroPrincipal';
    public static final String TOKEN_PARAMETER = 'ApiToken';

    /** Writes the External Credential principal. The real one calls ConnectApi. */
    public interface CredentialWriter {
        void write(ConnectApi.CredentialInput input);
    }

    // ConnectApi is not available in data-siloed tests. Tests inject a writer here;
    // without one, a test run skips the platform write.
    @TestVisible private static CredentialWriter testWriter;
    @TestVisible private static Boolean failProtectedWrite = false;

    public static Boolean hasToken() {
        return String.isNotBlank(readToken());
    }

    public static String readToken() {
        String protectedToken = protectedToken();
        if (String.isNotBlank(protectedToken)) return protectedToken;
        return readLegacyToken();
    }

    /** True while a token is still in the public Veleiro_Config__c field. Read only. */
    public static Boolean hasLegacyToken() {
        return String.isNotBlank(readLegacyToken());
    }

    public static Boolean platformAuthReady() {
        Veleiro_Secret__c secret = Veleiro_Secret__c.getOrgDefaults();
        return secret != null && secret.Platform_Auth__c == true && String.isNotBlank(secret.Api_Token__c);
    }

    /** True after a principal write succeeded in an earlier transaction and is not confirmed yet. */
    public static Boolean platformWritePending() {
        Veleiro_Secret__c secret = Veleiro_Secret__c.getOrgDefaults();
        return secret != null && secret.Platform_Write_Pending__c == true;
    }

    /**
     * Copies a legacy public token into the protected setting and, only then, clears
     * the public field. A failed protected write leaves the public token untouched
     * so the org keeps calling Veleiro. Returns true when a protected token is in place.
     */
    public static Boolean migrateLegacyToken() {
        String legacy = readLegacyToken();
        Boolean protectedReady = String.isNotBlank(protectedToken());
        if (String.isBlank(legacy)) return protectedReady;
        if (!protectedReady) {
            try {
                writeProtected(legacy, false);
            } catch (Exception e) {
                return false;
            }
        }
        try {
            clearLegacyTokens();
        } catch (Exception e) {
            // The protected copy is already there. The public field is cleared on a later run.
            return true;
        }
        return true;
    }

    /**
     * Admin save. ConnectApi runs before any DML. A platform failure still stores the token.
     * No callout here: the new token is confirmed by confirmPlatformAuth() in a later
     * transaction. Returns true when the principal write succeeded.
     */
    public static Boolean saveNewToken(String token) {
        if (String.isBlank(token)) return false;
        String clean = token.trim();
        Boolean written = writePlatformCredential(clean);
        writeProtected(clean, false, written);
        clearLegacyTokens();
        return written;
    }

    /**
     * Best-effort write of the token into the External Credential principal.
     * The post-install user usually does not have principal access, so this
     * often fails during upgrade. The admin action retries it. Failures are
     * recorded by exception type only — never with the token or a response body.
     */
    public static Boolean writePlatformCredential(String token) {
        if (String.isBlank(token)) return false;
        if (Test.isRunningTest() && testWriter == null) return false;
        try {
            String externalName = VeleiroSyncConfig.namespacePrefix() + EXTERNAL_CREDENTIAL;
            ConnectApi.CredentialInput input = credentialInput(externalName, token);
            if (testWriter != null) {
                testWriter.write(input);
                return true;
            }
            try {
                ConnectApi.NamedCredentials.updateCredential(input);
            } catch (Exception updateFailed) {
                ConnectApi.NamedCredentials.createCredential(input);
            }
            return true;
        } catch (Exception e) {
            recordPlatformFailure(e);
            return false;
        }
    }

    /**
     * Step one of platform auth: copies the stored token into the External Credential
     * and records whether that write succeeded. Makes no callout, because the write
     * leaves uncommitted work. Returns true when the write succeeded (or platform auth
     * is already ready). A failed write leaves the protected token in place and records
     * the exception type. Never called from a page-load method.
     */
    public static Boolean preparePlatformAuth() {
        if (platformAuthReady()) return true;
        String token = readToken();
        if (String.isBlank(token)) return false;
        Boolean written = writePlatformCredential(token);
        setPlatformWritePending(written);
        return written;
    }

    /**
     * Step two of platform auth, in a new transaction: GET /clients through the secure
     * Named Credential, then (after the callout) marks platform auth ready. Probes only
     * when an earlier principal write succeeded, so a stale principal never confirms a
     * different token. Returns true only when platform auth is ready. A failed probe
     * records the exception type and keeps the legacy credential path.
     */
    public static Boolean confirmPlatformAuth() {
        if (platformAuthReady()) return true;
        if (!platformWritePending() || String.isBlank(readToken())) return false;
        try {
            VeleiroApiClient.probeSecureCredential();
        } catch (Exception e) {
            recordPlatformFailure(e);
            return false;
        }
        markPlatformAuth();
        return true;
    }

    private static void recordPlatformFailure(Exception e) {
        try {
            String kind = (e == null) ? 'UnknownException' : e.getTypeName();
            VeleiroSyncConfig.recordError('External Credential setup skipped: ' + kind);
        } catch (Exception ignored) {
            System.debug(LoggingLevel.ERROR, 'Could not record platform setup failure: ' + ignored.getTypeName());
        }
    }

    public static void markPlatformAuth() {
        String token = protectedToken();
        if (String.isBlank(token)) token = readLegacyToken();
        if (String.isBlank(token)) return;
        writeProtected(token, true, false);
    }

    private static String protectedToken() {
        Veleiro_Secret__c secret = Veleiro_Secret__c.getOrgDefaults();
        return (secret == null) ? null : secret.Api_Token__c;
    }

    private static String readLegacyToken() {
        Veleiro_Config__c userLevel = Veleiro_Config__c.getInstance();
        if (userLevel != null && String.isNotBlank(userLevel.Api_Token__c)) return userLevel.Api_Token__c;
        Veleiro_Config__c orgLevel = Veleiro_Config__c.getOrgDefaults();
        if (orgLevel != null && String.isNotBlank(orgLevel.Api_Token__c)) return orgLevel.Api_Token__c;
        for (Veleiro_Config__c row : [
            SELECT Api_Token__c FROM Veleiro_Config__c WHERE Api_Token__c != null LIMIT 1
        ]) {
            return row.Api_Token__c;
        }
        return null;
    }

    private static void writeProtected(String token, Boolean platform) {
        writeProtected(token, platform, false);
    }

    private static void writeProtected(String token, Boolean platform, Boolean pending) {
        if (Test.isRunningTest() && failProtectedWrite == true) {
            throw new VeleiroApiClient.VeleiroApiException('Protected token write failed.');
        }
        Veleiro_Secret__c secret = Veleiro_Secret__c.getOrgDefaults();
        if (secret == null || secret.Id == null) {
            secret = new Veleiro_Secret__c(SetupOwnerId = UserInfo.getOrganizationId());
        }
        secret.Api_Token__c = token;
        secret.Platform_Auth__c = platform == true;
        secret.Platform_Write_Pending__c = pending == true;
        upsert secret;
    }

    private static void setPlatformWritePending(Boolean pending) {
        Veleiro_Secret__c secret = Veleiro_Secret__c.getOrgDefaults();
        Boolean value = pending == true;
        if (secret == null || secret.Id == null) {
            if (!value) return;
            secret = new Veleiro_Secret__c(SetupOwnerId = UserInfo.getOrganizationId());
        }
        if (secret.Platform_Write_Pending__c == value) return;
        secret.Platform_Write_Pending__c = value;
        upsert secret;
    }

    private static void clearLegacyTokens() {
        List<Veleiro_Config__c> rows = [
            SELECT Id, Api_Token__c FROM Veleiro_Config__c WHERE Api_Token__c != null
        ];
        if (rows.isEmpty()) return;
        for (Veleiro_Config__c row : rows) row.Api_Token__c = null;
        update rows;
    }

    private static ConnectApi.CredentialInput credentialInput(String externalName, String token) {
        ConnectApi.CredentialValueInput value = new ConnectApi.CredentialValueInput();
        value.encrypted = true;
        value.value = token;
        ConnectApi.CredentialInput input = new ConnectApi.CredentialInput();
        input.authenticationProtocol = ConnectApi.CredentialAuthenticationProtocol.Custom;
        input.externalCredential = externalName;
        input.principalName = PRINCIPAL;
        input.principalType = ConnectApi.CredentialPrincipalType.NamedPrincipal;
        input.credentials = new Map<String, ConnectApi.CredentialValueInput>{
            TOKEN_PARAMETER => value
        };
        return input;
    }
}
