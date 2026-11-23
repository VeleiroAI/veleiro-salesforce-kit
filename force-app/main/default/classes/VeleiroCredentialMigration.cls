/**
 * Best-effort move of the protected token into the External Credential principal.
 * Runs after install (the install script itself cannot call out). The install
 * user usually does not have External Credential principal access, so this
 * job often cannot finish the write; an administrator retries it with
 * VeleiroMappingController.secureLegacyToken(). Failures are recorded by
 * exception type only, so a Completed job is not silent success.
 * A failure leaves the legacy Named Credential path in place.
 *
 * Two jobs, because a callout cannot follow the ConnectApi write in the same
 * transaction: the first writes the principal, then queues a second job that
 * confirms it with GET /clients.
 */
public with sharing class VeleiroCredentialMigration implements Queueable, Database.AllowsCallouts {
    private final Boolean confirmStep;

    public VeleiroCredentialMigration() {
        this(false);
    }

    public VeleiroCredentialMigration(Boolean confirmStep) {
        this.confirmStep = confirmStep == true;
    }

    public void execute(QueueableContext context) {
        if (confirmStep) {
            VeleiroCredentialStore.confirmPlatformAuth();
            return;
        }
        if (!VeleiroCredentialStore.preparePlatformAuth() || VeleiroCredentialStore.platformAuthReady()) return;
        try {
            System.enqueueJob(new VeleiroCredentialMigration(true));
        } catch (Exception e) {
            // The admin action finishes the setup. Recorded by type only.
            VeleiroSyncConfig.recordError('External Credential setup skipped: ' + e.getTypeName());
        }
    }
}
