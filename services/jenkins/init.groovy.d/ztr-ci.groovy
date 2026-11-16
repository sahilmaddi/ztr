import hudson.plugins.git.BranchSpec
import hudson.plugins.git.GitSCM
import hudson.plugins.git.UserRemoteConfig
import jenkins.model.Jenkins
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob
import org.jenkinsci.plugins.gwt.GenericTrigger

def instance = Jenkins.get()
def adminId = System.getenv('JENKINS_ADMIN_ID')
def adminPassword = System.getenv('JENKINS_ADMIN_PASSWORD')
def repositoryOwner = System.getenv('GITEA_REPO_OWNER')
def repositoryName = System.getenv('GITEA_REPO_NAME')
def webhookToken = System.getenv('GITEA_WEBHOOK_TOKEN')

if ([adminId, adminPassword, repositoryOwner, repositoryName, webhookToken].any { !it }) {
    throw new IllegalStateException('Missing required local CI environment configuration.')
}

def realm = new HudsonPrivateSecurityRealm(false)
if (!realm.getUser(adminId)) {
    realm.createAccount(adminId, adminPassword)
}
instance.setSecurityRealm(realm)

def authorization = new FullControlOnceLoggedInAuthorizationStrategy()
authorization.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(authorization)

def jobName = 'ztr-ci'
def job = instance.getItem(jobName)
if (job == null) {
    job = instance.createProject(WorkflowJob, jobName)
}

def repositoryUrl = "http://gitea:3000/${repositoryOwner}/${repositoryName}.git"
def remote = new UserRemoteConfig(repositoryUrl, null, null, null)
def scm = new GitSCM(
    [remote],
    [new BranchSpec('*/main')],
    false,
    [],
    null,
    null,
    []
)
def definition = new CpsScmFlowDefinition(scm, 'Jenkinsfile')
definition.setLightweight(true)
job.setDefinition(definition)
def trigger = job.getTriggers().values().find { it instanceof GenericTrigger }
if (trigger == null) {
    trigger = new GenericTrigger([], [], [])
    job.addTrigger(trigger)
}
trigger.setToken(webhookToken)
trigger.setCauseString('Triggered by a Gitea push')
job.setConcurrentBuild(false)
job.save()

instance.save()
