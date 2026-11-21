#!/usr/bin/env python3
"""
Organization migration checks.

Run from the customer's AWS Organizations management account, read-only. Looks for
the things that break when the customer's member accounts leave their organization
and join one Pump provisions through Ingram, and writes one CSV row per finding.

Each finding has a severity that decides the onboarding path:

    blocker              on the "do not touch, auto CTA" list (Control Tower, closed
                         accounts, Identity Center applications or external IdP,
                         RAM shares, Application Migration Service, EDP/PPA) —
                         CTA onboarding, route to sales
    fix_before_move      breaks unless changed before the accounts leave
                         (org-scoped RAM shares, aws:PrincipalOrgID conditions, ...)
    reenable_after_move  stops on the move and has to be turned on again in the
                         new org (trusted access, delegated administrators, org trails)
    review               needs a conversation with the customer (third-party
                         integrations, how they use Config, ...)
    unverified           a check could not run (permissions, or out of reach of
                         a management-account scan)
    info                 context, no action

Checks run from the management account cover the organization's own configuration
(trusted access, delegated administrators, StackSets, org trails, Identity Center)
and the management account's own policies and RAM shares. Policies and RAM shares
that live in member accounts are only reachable through an organization Config
aggregator, when the customer has one; otherwise they are reported as unverified.
"""

import argparse
import csv
import json
import re
import sys
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import astuple, dataclass
from datetime import date, timedelta

try:
    import boto3
    import botocore.session
    from botocore.config import Config
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
    )
except ImportError:
    sys.exit("\nError: boto3 is not installed. Run: python3 -m pip install boto3 rich\n")


BLOCKER = "blocker"
FIX_BEFORE_MOVE = "fix_before_move"
REENABLE_AFTER_MOVE = "reenable_after_move"
REVIEW = "review"
UNVERIFIED = "unverified"
INFO = "info"

SEVERITY_ORDER = [BLOCKER, FIX_BEFORE_MOVE, REVIEW, REENABLE_AFTER_MOVE, UNVERIFIED, INFO]

COLS = ["Severity", "Service", "Check", "AccountID", "Region", "Resource", "Detail", "Action"]

CLIENT_CONFIG = Config(
    connect_timeout=10,
    read_timeout=30,
    retries={"max_attempts": 4, "mode": "adaptive"},
)

# Global services are called through one region. us-east-1 matches what
# inventory.get_all_regions uses for describe_regions.
GLOBAL_REGION = "us-east-1"

# Condition keys that compare the caller or the resource against an organization.
# Any of them in a policy stops matching once the account is in another org.
ORG_CONDITION_KEYS = (
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:resourceorgid",
    "aws:resourceorgpaths",
    "aws:sourceorgid",
    "aws:sourceorgpaths",
)

# RAM resource types where losing the share can cause downtime: workloads in a
# shared subnet, Transit Gateway attachments, resolver rules, prefix lists, IPAM.
NETWORK_RESOURCE_TYPE_PREFIXES = (
    "ec2:subnet",
    "ec2:transitgateway",
    "ec2:prefixlist",
    "ec2:ipampool",
    "route53resolver:",
    "network-firewall:",
    "vpc-lattice:",
)

CONTROL_TOWER_STACKSET_PREFIX = "AWSControlTowerBP-"

# Roles Control Tower creates in the management account when it sets up a landing zone.
CONTROL_TOWER_ROLE_NAMES = {
    "AWSControlTowerAdmin",
    "AWSControlTowerStackSetRole",
    "AWSControlTowerCloudTrailRole",
    "AWSControlTowerConfigAggregatorRoleForOrganizations",
}

# Services on the "DO NOT TOUCH - AUTO CTA" list in the "Automated Migration
# Checks" doc. Finding any of them in use is a blocker; failing to check one of
# them leaves the verdict undecided rather than "regular onboarding".
CONTROL_TOWER = "AWS Control Tower"
IDENTITY_CENTER = "AWS IAM Identity Center"
RAM = "AWS Resource Access Manager"
APPLICATION_MIGRATION = "AWS Application Migration Service"
PRIVATE_PRICING = "EDP / PPA"
AUTO_CTA_SERVICES = {CONTROL_TOWER, IDENTITY_CENTER, RAM, APPLICATION_MIGRATION, PRIVATE_PRICING}

# Account states for a closed account (Status is the older field, State the newer one).
CLOSED_ACCOUNT_STATES = {"SUSPENDED", "PENDING_CLOSURE", "CLOSED"}

# Cost Explorer RECORD_TYPE values for private pricing agreements.
PRIVATE_PRICING_RECORD_TYPES = {
    "Enterprise Discount Program Discount": "EDP",
    "Private Rate Card Discount": "PPA",
}
PRIVATE_PRICING_LOOKBACK_DAYS = 365

# Rows about whether the customer's people can still get into accounts after the move.
# Not on the do-not-touch list, so a failed check here does not make the verdict undecided.
ACCOUNT_ACCESS = "Account access"

# Values of the Resource column on "access after move" rows, one per member account.
# The backend can read these to hold an account's removal until there is a verified way in.
ACCESS_IDENTITY_CENTER_ONLY = "identity_center_only"
ACCESS_IDENTITY_CENTER_RECOVERABLE = "identity_center_recoverable"
ACCESS_NOT_IDENTITY_CENTER = "not_identity_center"
ACCESS_UNKNOWN = "unknown"

# Delegated administrators for these services are blockers, not just a deregistration step.
DELEGATED_ADMIN_BLOCKERS = {"mgn.amazonaws.com", "ram.amazonaws.com"}

# Trusted-access service principals mapped to the doc's guidance
# ("Automated Migration Checks"). Anything not listed falls back to
# reenable_after_move: the doc's default for an org-integrated service is
# "delegated admin — re-enable in the new org".
TRUSTED_ACCESS_RULES = {
    "controltower.amazonaws.com": (
        BLOCKER,
        CONTROL_TOWER,
        "Control Tower manages the accounts from the management account and breaks when they leave.",
        "Route to sales: the customer needs to keep access to their management account (CTA onboarding).",
    ),
    "mgn.amazonaws.com": (
        BLOCKER,
        APPLICATION_MIGRATION,
        "Application Migration Service is integrated with the organization.",
        "Route to sales: Application Migration Service is on the do-not-touch list (CTA onboarding).",
    ),
    "ram.amazonaws.com": (
        REVIEW,
        RAM,
        "RAM sharing with the organization is enabled, so accounts can share resources with the whole org or with OUs.",
        "See the RAM rows: any share in use means CTA onboarding.",
    ),
    "account.amazonaws.com": (
        INFO,
        "AWS Account Management",
        "Account Management is integrated with the organization. Not breaking unless the customer uses TEAM.",
        "If TEAM is in use (see Identity Center rows), re-enable through a delegated admin in the new org.",
    ),
    "sso.amazonaws.com": (
        FIX_BEFORE_MOVE,
        IDENTITY_CENTER,
        "Identity Center is integrated with the organization; SSO access to moved accounts stops when they leave.",
        "Recreate users, groups and permission sets in the new org; make sure every account has an IAM user or role the customer can reach without SSO.",
    ),
    "member.org.stacksets.cloudformation.amazonaws.com": (
        REENABLE_AFTER_MOVE,
        "AWS CloudFormation StackSets",
        "Service-managed StackSets are enabled for the organization.",
        "Enable trusted access for CloudFormation in the new org; see the StackSet rows for what to do before the move.",
    ),
    "config.amazonaws.com": (
        REVIEW,
        "AWS Config",
        "AWS Config is integrated with the organization. Not breaking.",
        "Ask how they use Config before the move; re-enable through a delegated admin in the new org.",
    ),
    "config-multiaccountsetup.amazonaws.com": (
        REVIEW,
        "AWS Config",
        "AWS Config organization rules / conformance packs are enabled. Not breaking.",
        "Ask how they use Config before the move; re-enable through a delegated admin in the new org.",
    ),
    "compute-optimizer.amazonaws.com": (
        INFO,
        "AWS Compute Optimizer",
        "Compute Optimizer is integrated with the organization. Not breaking.",
        "Re-enable through a delegated admin in the new org if they want it.",
    ),
    "iam.amazonaws.com": (
        REENABLE_AFTER_MOVE,
        "AWS Identity and Access Management",
        "IAM is integrated with the organization (centralized root access).",
        "Deregister the IAM delegated admin before the move; set it up again in the new org.",
    ),
}


@dataclass
class Finding:
    severity: str
    service: str
    check: str
    account_id: str = ""
    region: str = ""
    resource: str = ""
    detail: str = ""
    action: str = ""

    def as_row(self):
        return dict(zip(COLS, astuple(self)))


def paginate(method, result_key, token_in="NextToken", token_out=None, **kwargs):
    """Yield every item of *result_key* across pages of *method*.

    Done by hand rather than with get_paginator so the same loop covers the APIs
    that name their token differently (RAM's nextToken, IAM's Marker).
    """
    token_out = token_out or token_in
    while True:
        response = method(**kwargs)
        yield from response.get(result_key, [])
        next_token = response.get(token_out)
        if not next_token:
            return
        kwargs[token_in] = next_token


def iam_paginate(method, **kwargs):
    """IAM pages carry IsTruncated + Marker and return several result lists per page."""
    while True:
        response = method(**kwargs)
        yield response
        if not response.get("IsTruncated"):
            return
        kwargs["Marker"] = response["Marker"]


def org_condition_keys_in(document) -> list[str]:
    """Organization condition keys used anywhere in a policy document.

    *document* may be a dict (boto3 decodes IAM documents) or a string, possibly
    URL-encoded (Config stores IAM documents that way).
    """
    text = document if isinstance(document, str) else json.dumps(document)
    text = urllib.parse.unquote(text).lower()
    return [key for key in ORG_CONDITION_KEYS if key in text]


def is_org_scoped_principal(principal_id: str) -> bool:
    """RAM principals that name an organization or OU instead of an account."""
    return ":organization/" in principal_id or ":ou/" in principal_id


def is_network_resource_type(resource_type: str) -> bool:
    lowered = resource_type.lower()
    return any(lowered.startswith(prefix) for prefix in NETWORK_RESOURCE_TYPE_PREFIXES)


class OrgChecks:
    """Runs every check against one boto3 session and collects findings."""

    def __init__(self, session, regions=None, max_workers=8):
        self.session = session
        self.requested_regions = regions
        self.max_workers = max_workers
        self.findings: list[Finding] = []
        self._findings_lock = threading.Lock()
        # boto3 sessions are not thread-safe for client creation.
        self._client_lock = threading.Lock()
        self.caller_account_id = ""
        self.org_id = ""
        self.org_account_ids: set[str] = set()
        self.is_management_account = False
        self.has_organization = False
        # Set by check_control_tower; other checks use it to decide whether Control
        # Tower traces (its stack sets, its IAM roles) are already covered.
        self.control_tower_found = False
        # Set by check_trusted_access. None means trusted access could not be read.
        self.ram_org_sharing_enabled = None
        self.caller_arn = ""
        # Every account in the org, from ListAccounts: Id, Name, Status, JoinedMethod.
        self.org_accounts: list[dict] = []
        # Accounts with an Identity Center permission set provisioned. None until read, so a
        # failed read is told apart from "no assignments".
        self.identity_center_instances = 0
        self.identity_center_accounts: set[str] | None = None
        self._identity_center_lock = threading.Lock()
        self._bucket_names_listed = False
        self._bucket_names = None
        self._bucket_names_lock = threading.Lock()

    # ── plumbing ──

    def client(self, service, region=GLOBAL_REGION):
        with self._client_lock:
            return self.session.client(service, region_name=region, config=CLIENT_CONFIG)

    def add(self, finding: Finding):
        with self._findings_lock:
            self.findings.append(finding)

    @contextmanager
    def guard(self, service, check, region="", resource=""):
        """Turn an API failure into an unverified finding instead of aborting the scan."""
        try:
            yield
        except EndpointConnectionError:
            # The service has no endpoint in this region: nothing to check there.
            return
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "ClientError")
            message = error.response.get("Error", {}).get("Message", "")
            self.add(Finding(
                severity=UNVERIFIED,
                service=service,
                check=check,
                account_id=self.caller_account_id,
                region=region,
                resource=resource,
                detail=f"{code}: {message}"[:500],
                action="Check by hand, or rerun with credentials that allow this call.",
            ))
        except Exception as error:  # noqa: BLE001 - one failed check must not end the scan
            self.add(Finding(
                severity=UNVERIFIED,
                service=service,
                check=check,
                account_id=self.caller_account_id,
                region=region,
                resource=resource,
                detail=f"{type(error).__name__}: {error}"[:500],
                action="Check by hand, or rerun.",
            ))

    def regions(self):
        if self.requested_regions:
            regions = list(self.requested_regions)
            self.add(Finding(
                severity=UNVERIFIED,
                service="Scan scope",
                check="regions",
                account_id=self.caller_account_id,
                detail=(
                    f"Regional checks ran only in {', '.join(regions)}. StackSets, trails, RAM shares, "
                    "Identity Center and observability sinks in other regions were not scanned."
                ),
                action="Rerun without --region (or with --all-regions on `run`).",
            ))
            return regions
        try:
            response = self.client("ec2").describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            return sorted(region["RegionName"] for region in response["Regions"])
        except (ClientError, BotoCoreError) as error:
            self.add(Finding(
                severity=UNVERIFIED,
                service="Scan scope",
                check="regions",
                account_id=self.caller_account_id,
                detail=f"Could not list regions ({type(error).__name__}: {error}); scanned {GLOBAL_REGION} only."[:500],
                action="Rerun with ec2:DescribeRegions allowed.",
            ))
            return [GLOBAL_REGION]

    # ── entry point ──

    def run(self):
        identity = self.client("sts").get_caller_identity()
        self.caller_account_id = identity["Account"]
        self.caller_arn = identity.get("Arn", "")
        self.check_organization()
        if not self.has_organization:
            return self.findings

        if self.is_management_account:
            self.check_trusted_access()
            self.check_delegated_administrators()
            self.check_control_tower()
            self.check_org_policies()
            self.check_private_pricing()

        regions = self.regions()
        regional_checks = [
            self.check_stack_sets,
            self.check_cloudtrail,
            self.check_ram_shares,
            self.check_identity_center,
            self.check_observability_links,
            self.check_application_migration,
        ]
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self.check_management_account_iam), pool.submit(self.check_management_account_buckets)]
            futures += [pool.submit(check, region) for region in regions for check in regional_checks]
            for future in futures:
                future.result()

        self.check_member_accounts(regions)
        if self.is_management_account:
            self.check_account_access()
        self.add(Finding(
            severity=UNVERIFIED,
            service="Scan scope",
            check="not covered",
            account_id=self.caller_account_id,
            detail=(
                "Not checked by this scan: org conditions in resource policies on SSM parameters, KMS keys, "
                "SNS topics, SQS queues, Lambda functions, EventBridge buses, Secrets Manager secrets, ECR "
                "repositories and Backup vaults; AMIs and snapshots shared with an org or OU; CloudTrail Lake "
                "organization event data stores; Application Migration Service used in member accounts without "
                "trusted access; "
                "third-party integrations through S3 notifications or log subscription filters."
            ),
            action="Cover these with the customer on the AE checklist.",
        ))
        return self.findings

    # ── organization ──

    def check_organization(self):
        organizations = self.client("organizations")
        try:
            organization = organizations.describe_organization()["Organization"]
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code == "AWSOrganizationsNotInUseException":
                self.add(Finding(
                    severity=INFO,
                    service="AWS Organizations",
                    check="organization",
                    account_id=self.caller_account_id,
                    detail="This account is not in an AWS Organization. Nothing org-level can break.",
                    action="Regular onboarding.",
                ))
                return
            self.add(Finding(
                severity=UNVERIFIED,
                service="AWS Organizations",
                check="organization",
                account_id=self.caller_account_id,
                detail=f"Could not read the organization: {code}: {error.response.get('Error', {}).get('Message', '')}"[:500],
                action="Rerun from the management account with organizations:DescribeOrganization allowed.",
            ))
            return

        self.has_organization = True
        self.org_id = organization["Id"]
        management_account_id = organization["MasterAccountId"]
        self.is_management_account = management_account_id == self.caller_account_id

        if not self.is_management_account:
            self.add(Finding(
                severity=UNVERIFIED,
                service="AWS Organizations",
                check="organization",
                account_id=self.caller_account_id,
                resource=self.org_id,
                detail=(
                    f"Ran from member account {self.caller_account_id}, not the management account "
                    f"{management_account_id}. Trusted access, delegated administrators and "
                    "service-managed StackSets can only be read from the management account."
                ),
                action="Rerun from the management account.",
            ))
            return

        with self.guard("AWS Organizations", "accounts"):
            accounts = list(paginate(organizations.list_accounts, "Accounts"))
            self.org_accounts = accounts
            self.org_account_ids = {account["Id"] for account in accounts if account.get("Status") == "ACTIVE"}
            for account in accounts:
                state = account.get("State") or account.get("Status", "")
                if state not in CLOSED_ACCOUNT_STATES:
                    continue
                self.add(Finding(
                    severity=BLOCKER,
                    service="AWS Organizations",
                    check="closed account",
                    account_id=account["Id"],
                    resource=account.get("Name", account["Id"]),
                    detail=f"Account is {state.lower().replace('_', ' ')}. Closed accounts are on the do-not-touch list.",
                    action="Route to sales (CTA onboarding).",
                ))
            self.add(Finding(
                severity=INFO,
                service="AWS Organizations",
                check="organization",
                account_id=self.caller_account_id,
                resource=self.org_id,
                detail=f"Management account of {self.org_id} with {len(self.org_account_ids)} active accounts.",
            ))

    def check_trusted_access(self):
        organizations = self.client("organizations")
        with self.guard("AWS Organizations", "trusted access"):
            enabled = list(paginate(
                organizations.list_aws_service_access_for_organization, "EnabledServicePrincipals"
            ))
            self.ram_org_sharing_enabled = any(
                service_access["ServicePrincipal"] == "ram.amazonaws.com" for service_access in enabled
            )
            for service_access in enabled:
                principal = service_access["ServicePrincipal"]
                severity, service, detail, action = TRUSTED_ACCESS_RULES.get(principal, (
                    REENABLE_AFTER_MOVE,
                    principal,
                    f"{principal} has trusted access to the organization.",
                    "Re-enable trusted access (and its delegated admin, if any) in the new org.",
                ))
                self.add(Finding(
                    severity=severity,
                    service=service,
                    check="trusted access",
                    account_id=self.caller_account_id,
                    resource=principal,
                    detail=detail,
                    action=action,
                ))

    def check_delegated_administrators(self):
        organizations = self.client("organizations")
        with self.guard("AWS Organizations", "delegated administrators"):
            admins = list(paginate(organizations.list_delegated_administrators, "DelegatedAdministrators"))
            for admin in admins:
                services = list(paginate(
                    organizations.list_delegated_services_for_account,
                    "DelegatedServices",
                    AccountId=admin["Id"],
                ))
                for delegated in services:
                    principal = delegated["ServicePrincipal"]
                    is_blocker = principal in DELEGATED_ADMIN_BLOCKERS
                    self.add(Finding(
                        severity=BLOCKER if is_blocker else FIX_BEFORE_MOVE,
                        service=TRUSTED_ACCESS_RULES.get(principal, (None, principal))[1],
                        check="delegated administrator",
                        account_id=admin["Id"],
                        resource=principal,
                        detail=f"{admin.get('Name', admin['Id'])} is delegated administrator for {principal}.",
                        action=(
                            "Route to sales: this service is on the do-not-touch list (CTA onboarding)."
                            if is_blocker else
                            "Deregister before the move; register the account again in the new org."
                        ),
                    ))

    def check_control_tower(self):
        """Look for a landing zone directly.

        Trusted access alone misses it: a live landing zone does not always list
        controltower.amazonaws.com among the enabled service principals (seen on a
        test org whose landing zone is ACTIVE). ListLandingZones answers from any
        region with the landing zone's ARN, which names its home region.

        ReadOnlyAccess does not grant controltower:ListLandingZones or
        GetLandingZone, so a customer running with only that policy gets an
        unverified row here. Control Tower's stack sets and IAM roles are readable
        with ReadOnlyAccess; check_stack_sets and check_management_account_iam
        report those as blockers when no landing zone was found here.
        """
        controltower = self.client("controltower")
        with self.guard(CONTROL_TOWER, "landing zone"):
            landing_zones = list(paginate(controltower.list_landing_zones, "landingZones", token_in="nextToken"))
            for landing_zone in landing_zones:
                self.control_tower_found = True
                arn = landing_zone["arn"]
                home_region = arn.split(":")[3]
                details = self.client("controltower", home_region).get_landing_zone(
                    landingZoneIdentifier=arn
                )["landingZone"]
                self.add(Finding(
                    severity=BLOCKER,
                    service=CONTROL_TOWER,
                    check="landing zone",
                    account_id=self.caller_account_id,
                    region=home_region,
                    resource=arn,
                    detail=(
                        f"Control Tower landing zone, version {details.get('version', '?')}, "
                        f"status {details.get('status', '?')}, drift {details.get('driftStatus', {}).get('status', '?')}. "
                        "Control Tower manages the accounts from the management account and breaks when they leave."
                    ),
                    action="Route to sales: the customer needs to keep access to their management account (CTA onboarding).",
                ))

    def check_org_policies(self):
        """Customer-managed organization policies (SCPs, backup, tag, ...) stop applying on the move."""
        organizations = self.client("organizations")
        policy_types = organizations.meta.service_model.operation_model("ListPolicies").input_shape.members["Filter"].enum
        for policy_type in policy_types:
            with self.guard("AWS Organizations", "organization policies", resource=policy_type):
                policies = list(paginate(organizations.list_policies, "Policies", Filter=policy_type))
                for policy in policies:
                    if policy.get("AwsManaged"):
                        # e.g. FullAWSAccess: exists in every org.
                        continue
                    self.add(Finding(
                        severity=REENABLE_AFTER_MOVE,
                        service="AWS Organizations",
                        check="organization policy",
                        account_id=self.caller_account_id,
                        resource=policy.get("Name", policy.get("Id", "")),
                        detail=f"{policy_type} '{policy.get('Name', '')}' stops applying to accounts that leave the org.",
                        action="Recreate it in the new org if the customer still wants it enforced.",
                    ))

    def check_private_pricing(self):
        """EDP or PPA discounts on the bill in the last year."""
        cost_explorer = self.client("ce")
        end = date.today()
        start = end - timedelta(days=PRIVATE_PRICING_LOOKBACK_DAYS)
        with self.guard(PRIVATE_PRICING, "discount record types"):
            record_types = [
                value["Value"] for value in paginate(
                    cost_explorer.get_dimension_values, "DimensionValues", token_in="NextPageToken",
                    TimePeriod={"Start": start.isoformat(), "End": end.isoformat()}, Dimension="RECORD_TYPE",
                )
            ]
            agreements = sorted(
                PRIVATE_PRICING_RECORD_TYPES[record_type]
                for record_type in record_types if record_type in PRIVATE_PRICING_RECORD_TYPES
            )
            if agreements:
                self.add(Finding(
                    severity=BLOCKER,
                    service=PRIVATE_PRICING,
                    check="private pricing agreement",
                    account_id=self.caller_account_id,
                    resource=", ".join(agreements),
                    detail=f"The bill carries {' and '.join(agreements)} discounts since {start.isoformat()}.",
                    action="Route to sales: EDP / PPA is on the do-not-touch list (CTA onboarding).",
                ))
            else:
                self.add(Finding(
                    severity=INFO,
                    service=PRIVATE_PRICING,
                    check="private pricing agreement",
                    account_id=self.caller_account_id,
                    detail=f"No EDP or PPA discounts on the bill since {start.isoformat()}.",
                ))

    # ── StackSets ──

    def check_stack_sets(self, region):
        if not self.is_management_account:
            return
        cloudformation = self.client("cloudformation", region)
        with self.guard("AWS CloudFormation StackSets", "stack sets", region):
            summaries = list(paginate(
                cloudformation.list_stack_sets, "Summaries", Status="ACTIVE", CallAs="SELF"
            ))
            for summary in summaries:
                name = summary["StackSetName"]
                permission_model = summary.get("PermissionModel", "SELF_MANAGED")
                if name.startswith(CONTROL_TOWER_STACKSET_PREFIX):
                    if self.control_tower_found:
                        self.add(Finding(
                            severity=INFO,
                            service="AWS CloudFormation StackSets",
                            check="stack set",
                            account_id=self.caller_account_id,
                            region=region,
                            resource=name,
                            detail="Managed by Control Tower; covered by the Control Tower landing zone finding.",
                        ))
                    else:
                        self.add(Finding(
                            severity=BLOCKER,
                            service=CONTROL_TOWER,
                            check="control tower stack set",
                            account_id=self.caller_account_id,
                            region=region,
                            resource=name,
                            detail=(
                                "Control Tower's own stack set is active, so Control Tower is (or was) set up. "
                                "The landing zone itself could not be read."
                            ),
                            action=(
                                "Route to sales unless the customer confirms Control Tower was decommissioned "
                                "(CTA onboarding)."
                            ),
                        ))
                    continue

                instances = list(paginate(
                    cloudformation.list_stack_instances, "Summaries", StackSetName=name, CallAs="SELF"
                ))
                instance_accounts = {instance["Account"] for instance in instances}

                if permission_model != "SERVICE_MANAGED":
                    self.add(Finding(
                        severity=INFO,
                        service="AWS CloudFormation StackSets",
                        check="stack set",
                        account_id=self.caller_account_id,
                        region=region,
                        resource=name,
                        detail=(
                            f"Self-managed stack set, {len(instances)} instances in "
                            f"{len(instance_accounts)} accounts. Uses explicit execution roles, "
                            "not org membership."
                        ),
                        action="None unless the execution roles trust the admin account through aws:PrincipalOrgID.",
                    ))
                    continue

                # The summary carries AutoDeployment too, but DescribeStackSet is the
                # documented home for it; one call per service-managed stack set.
                stack_set = cloudformation.describe_stack_set(StackSetName=name, CallAs="SELF")["StackSet"]
                auto_deployment = stack_set.get("AutoDeployment") or summary.get("AutoDeployment") or {}
                auto_deploys = bool(auto_deployment.get("Enabled"))
                retains = bool(auto_deployment.get("RetainStacksOnAccountRemoval"))
                drift = summary.get("DriftStatus", "NOT_CHECKED")
                # Instances are only removed (and their resources deleted) on account
                # removal when automatic deployment is on and retention is off.
                deletes_on_removal = auto_deploys and not retains
                if deletes_on_removal:
                    removal = (
                        "Automatic deployment is on and RetainStacksOnAccountRemoval is off: when an "
                        "account leaves the org its stack instance is removed and the stack's resources are DELETED."
                    )
                    action = (
                        "Set RetainStacksOnAccountRemoval=true before the move; after it, run drift "
                        "detection and import the retained stacks into a stack set in the new org "
                        "(import-stacks-to-stack-set)."
                    )
                elif auto_deploys:
                    removal = "RetainStacksOnAccountRemoval is on, so stacks stay in accounts that leave."
                    action = (
                        "After the move, run drift detection and import the retained stacks into a "
                        "stack set in the new org (import-stacks-to-stack-set)."
                    )
                else:
                    removal = (
                        "Automatic deployment is off, so stacks stay in accounts that leave but are no "
                        "longer managed by this stack set."
                    )
                    action = (
                        "After the move, run drift detection and import the stacks into a stack set in "
                        "the new org (import-stacks-to-stack-set)."
                    )
                self.add(Finding(
                    severity=FIX_BEFORE_MOVE if deletes_on_removal else REENABLE_AFTER_MOVE,
                    service="AWS CloudFormation StackSets",
                    check="service-managed stack set",
                    account_id=self.caller_account_id,
                    region=region,
                    resource=name,
                    detail=(
                        f"{len(instances)} instances in {len(instance_accounts)} accounts. "
                        f"{removal} Drift status: {drift}."
                    ),
                    action=action,
                ))

    # ── CloudTrail ──

    def check_cloudtrail(self, region):
        cloudtrail = self.client("cloudtrail", region)
        with self.guard("AWS CloudTrail", "trails", region):
            # includeShadowTrails=False: each trail is reported once, in its home region.
            trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
            for trail in trails:
                name = trail.get("Name", "")
                if trail.get("IsOrganizationTrail"):
                    self.add(Finding(
                        severity=REENABLE_AFTER_MOVE,
                        service="AWS CloudTrail",
                        check="organization trail",
                        account_id=self.caller_account_id,
                        region=region,
                        resource=name,
                        detail="Organization trail: stops logging moved accounts once they leave.",
                        action="Set up an organization trail in the new org (delegated admin), or trails per account.",
                    ))

                bucket = trail.get("S3BucketName")
                own_buckets = self._caller_bucket_names()
                if bucket and own_buckets is not None and bucket not in own_buckets:
                    self.add(Finding(
                        severity=REVIEW,
                        service="AWS CloudTrail",
                        check="trail destination",
                        account_id=self.caller_account_id,
                        region=region,
                        resource=name,
                        detail=f"Delivers to S3 bucket {bucket}, which this account does not own.",
                        action=(
                            "Ask who owns the bucket and what reads it (e.g. a Datadog or SIEM "
                            "integration); its bucket policy may use org condition keys."
                        ),
                    ))
                topic = trail.get("SnsTopicARN")
                if topic:
                    self.add(Finding(
                        severity=REVIEW,
                        service="AWS CloudTrail",
                        check="trail destination",
                        account_id=self.caller_account_id,
                        region=region,
                        resource=name,
                        detail=f"Publishes delivery notifications to {topic}.",
                        action="Ask what subscribes to the topic; third-party integrations often do.",
                    ))

    def _caller_bucket_names(self) -> set[str] | None:
        """Names of this account's buckets, or None when they can't be listed."""
        with self._bucket_names_lock:
            if not self._bucket_names_listed:
                self._bucket_names_listed = True
                try:
                    buckets = self.client("s3").list_buckets().get("Buckets", [])
                    self._bucket_names = {bucket["Name"] for bucket in buckets}
                except (ClientError, BotoCoreError):
                    self._bucket_names = None
            return self._bucket_names

    # ── RAM ──

    def check_ram_shares(self, region):
        ram = self.client("ram", region)
        owned = []
        with self.guard(RAM, "owned shares", region):
            owned = list(paginate(
                ram.get_resource_shares, "resourceShares", token_in="nextToken",
                resourceOwner="SELF", resourceShareStatus="ACTIVE",
            ))
        for share in owned:
            with self.guard(RAM, "owned share", region, share.get("name", "")):
                self._check_owned_share(ram, region, share)

        consumed = []
        with self.guard(RAM, "consumed shares", region):
            consumed = list(paginate(
                ram.get_resource_shares, "resourceShares", token_in="nextToken",
                resourceOwner="OTHER-ACCOUNTS", resourceShareStatus="ACTIVE",
            ))
        for share in consumed:
            with self.guard(RAM, "consumed share", region, share.get("name", "")):
                share_arn = share["resourceShareArn"]
                resources = list(paginate(
                    ram.list_resources, "resources", token_in="nextToken",
                    resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[share_arn],
                ))
                types = _type_counts(resource["type"] for resource in resources)
                networking = any(is_network_resource_type(resource["type"]) for resource in resources)
                impact = (
                    "Includes networking resources, which can mean downtime. " if networking else ""
                )
                self.add(Finding(
                    severity=BLOCKER,
                    service=RAM,
                    check="consumed share",
                    account_id=self.caller_account_id,
                    region=region,
                    resource=share.get("name", share_arn),
                    detail=(
                        f"Shared with this account by {share.get('owningAccountId', '?')}: {types or 'no resources'}. "
                        f"{impact}If the owner shared it with the org or an OU, access ends on the move."
                    ),
                    action="Route to sales: RAM is on the do-not-touch list (CTA onboarding).",
                ))

    def _check_owned_share(self, ram, region, share):
        share_arn = share["resourceShareArn"]
        principals = list(paginate(
            ram.list_principals, "principals", token_in="nextToken",
            resourceOwner="SELF", resourceShareArns=[share_arn],
        ))
        resources = list(paginate(
            ram.list_resources, "resources", token_in="nextToken",
            resourceOwner="SELF", resourceShareArns=[share_arn],
        ))
        org_principals = [principal["id"] for principal in principals if is_org_scoped_principal(principal["id"])]
        account_principals = [
            principal["id"] for principal in principals
            if principal["id"].isdigit() or ":iam::" in principal["id"]
        ]
        types = _type_counts(resource["type"] for resource in resources)
        networking = any(is_network_resource_type(resource["type"]) for resource in resources)
        allows_external = bool(share.get("allowExternalPrincipals"))
        name = share.get("name", share_arn)

        if org_principals:
            check = "org-scoped share"
            impact = (
                "Networking resources: workloads in moved accounts keep existing ENIs/attachments "
                "but can't create new ones in the shared subnet or TGW."
                if networking else
                "Moved accounts lose access to these resources immediately."
            )
            shared_with = ", ".join(org_principals)
        else:
            check = "account share"
            impact = (
                "External principals are off, so once the accounts are in another org they are "
                "outside this share's allowed principals."
                if account_principals and not allows_external else
                "Shared with explicit principals."
            )
            shared_with = f"{len(account_principals)} accounts or IAM principals"
            if not principals:
                impact = "No principals are associated with it right now."
                shared_with = "no one"
        self.add(Finding(
            severity=BLOCKER,
            service=RAM,
            check=check,
            account_id=self.caller_account_id,
            region=region,
            resource=name,
            detail=f"Shared with {shared_with}: {types or 'no resources'}. {impact}",
            action="Route to sales: RAM is on the do-not-touch list (CTA onboarding).",
        ))

    # ── IAM Identity Center ──

    def check_identity_center(self, region):
        sso_admin = self.client("sso-admin", region)
        with self.guard(IDENTITY_CENTER, "instances", region):
            instances = list(paginate(sso_admin.list_instances, "Instances"))
            for instance in instances:
                self._check_identity_center_instance(sso_admin, region, instance)

    def _check_identity_center_instance(self, sso_admin, region, instance):
        instance_arn = instance["InstanceArn"]
        identity_store_id = instance.get("IdentityStoreId")

        permission_sets = list(paginate(sso_admin.list_permission_sets, "PermissionSets", InstanceArn=instance_arn))
        with self._identity_center_lock:
            self.identity_center_instances += 1
        with self.guard(ACCOUNT_ACCESS, "identity center accounts", region, instance_arn):
            covered = set()
            for permission_set in permission_sets:
                covered.update(paginate(
                    sso_admin.list_accounts_for_provisioned_permission_set, "AccountIds",
                    InstanceArn=instance_arn, PermissionSetArn=permission_set,
                ))
            with self._identity_center_lock:
                self.identity_center_accounts = (self.identity_center_accounts or set()) | covered
        self.add(Finding(
            severity=FIX_BEFORE_MOVE,
            service=IDENTITY_CENTER,
            check="instance",
            account_id=instance.get("OwnerAccountId", self.caller_account_id),
            region=region,
            resource=instance_arn,
            detail=f"Identity Center with {len(permission_sets)} permission sets. SSO into moved accounts stops when they leave.",
            action=(
                "Run the recreate script for users, groups and permission sets in the new org and "
                "delegate admin to a customer account; confirm each account has an IAM user or role "
                "the customer can reach without SSO."
            ),
        ))

        with self.guard(IDENTITY_CENTER, "applications", region):
            applications = list(paginate(sso_admin.list_applications, "Applications", InstanceArn=instance_arn))
            for application in applications:
                name = application.get("Name", application.get("ApplicationArn", ""))
                provider = application.get("ApplicationProviderArn", "")
                # Case-sensitive TEAM so "Data Team Portal" doesn't match.
                looks_like_team = bool(
                    re.search(r"\bTEAM\b", name) or re.search(r"temporary elevated access", name, re.IGNORECASE)
                )
                detail = f"Application '{name}' (provider {provider or 'unknown'}) does not copy to a new org."
                if looks_like_team:
                    detail += " Looks like TEAM, which also relies on Account Management delegated admin."
                self.add(Finding(
                    severity=BLOCKER,
                    service=IDENTITY_CENTER,
                    check="application",
                    account_id=instance.get("OwnerAccountId", self.caller_account_id),
                    region=region,
                    resource=name,
                    detail=detail,
                    action="Route to sales: Identity Center applications are on the do-not-touch list (CTA onboarding).",
                ))

        if identity_store_id:
            with self.guard(IDENTITY_CENTER, "identity source", region):
                identity_store = self.client("identitystore", region)
                users = list(paginate(identity_store.list_users, "Users", IdentityStoreId=identity_store_id))
                external_issuers = sorted({
                    external.get("Issuer", "")
                    for user in users
                    for external in (user.get("ExternalIds") or [])
                })
                if external_issuers:
                    self.add(Finding(
                        severity=BLOCKER,
                        service=IDENTITY_CENTER,
                        check="external identity provider",
                        account_id=instance.get("OwnerAccountId", self.caller_account_id),
                        region=region,
                        resource=identity_store_id,
                        detail=f"Users are provisioned from an external IdP (SCIM issuer: {', '.join(external_issuers)}).",
                        action=(
                            "Route to sales: an external identity provider is on the do-not-touch list "
                            "(CTA onboarding); the customer would have to reconfigure SAML and SCIM themselves."
                        ),
                    ))
                elif not users:
                    self.add(Finding(
                        severity=INFO,
                        service=IDENTITY_CENTER,
                        check="identity source",
                        account_id=instance.get("OwnerAccountId", self.caller_account_id),
                        region=region,
                        resource=identity_store_id,
                        detail="The identity store has no users, so no one signs in through Identity Center.",
                    ))
                else:
                    # SAML without SCIM leaves no ExternalIds, and there is no public
                    # API for the identity source, so absence proves nothing.
                    self.add(Finding(
                        severity=UNVERIFIED,
                        service=IDENTITY_CENTER,
                        check="identity source",
                        account_id=instance.get("OwnerAccountId", self.caller_account_id),
                        region=region,
                        resource=identity_store_id,
                        detail=(
                            f"None of the {len(users)} users were provisioned through SCIM. The identity "
                            "source can't be read through the API, so an external IdP over SAML alone is still possible."
                        ),
                        action=(
                            "Ask whether they sign in through Okta, Google Workspace, Entra, Rippling or "
                            "similar; if they do, it is CTA onboarding."
                        ),
                    ))

    # ── Application Migration Service ──

    def check_application_migration(self, region):
        """Source servers replicating into this account. Regions where the service was never
        set up answer UninitializedAccountException."""
        mgn = self.client("mgn", region)
        with self.guard(APPLICATION_MIGRATION, "source servers", region):
            try:
                servers = list(paginate(
                    mgn.describe_source_servers, "items", token_in="nextToken", filters={"isArchived": False},
                ))
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") == "UninitializedAccountException":
                    return
                raise
            if not servers:
                return
            states = _type_counts(
                server.get("lifeCycle", {}).get("state", "UNKNOWN") for server in servers
            )
            self.add(Finding(
                severity=BLOCKER,
                service=APPLICATION_MIGRATION,
                check="source servers",
                account_id=self.caller_account_id,
                region=region,
                resource=f"{len(servers)} source servers",
                detail=f"Application Migration Service has {len(servers)} source servers that are not archived ({states}).",
                action="Route to sales: Application Migration Service is on the do-not-touch list (CTA onboarding).",
            ))

    # ── account access after the move ──

    def check_account_access(self):
        """Whether the customer's people can still get into each account after it moves.

        Identity Center access to a member account is an AWSReservedSSO_* role that Identity
        Center removes when the account leaves the org. If that is the only way in (no IAM
        user with a console password, no usable root login), the customer is locked out
        until Identity Center is rebuilt in the new org.

        Member-account IAM users and root passwords can't be read from the management
        account, so per-account results say what radar could see and no more.
        """
        caller_kind = _caller_kind(self.caller_arn)
        self.add(Finding(
            severity=INFO,
            service=ACCOUNT_ACCESS,
            check="scan identity",
            account_id=self.caller_account_id,
            resource=self.caller_arn,
            detail=f"The scan ran as {caller_kind}.",
        ))

        iam = self.client("iam")
        root_features = None
        with self.guard(ACCOUNT_ACCESS, "centralized root access"):
            try:
                root_features = iam.list_organizations_features().get("EnabledFeatures", [])
            except ClientError as error:
                # Centralized root access needs IAM trusted access; without it the feature is off.
                if error.response.get("Error", {}).get("Code") != "ServiceAccessNotEnabledException":
                    raise
                root_features = []

        root_password = None
        with self.guard(ACCOUNT_ACCESS, "management account root password"):
            root_password = bool(iam.get_account_summary()["SummaryMap"].get("AccountPasswordPresent"))

        console_users = None
        with self.guard(ACCOUNT_ACCESS, "management account console users"):
            names = [user["UserName"] for page in iam_paginate(iam.list_users) for user in page.get("Users", [])]
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                has_password = list(pool.map(lambda name: _has_login_profile(iam, name), names))
            console_users = [name for name, present in zip(names, has_password) if present]

        # The old management account is a way back into accounts Organizations created:
        # their OrganizationAccountAccessRole trusts it, with no org condition.
        management_login = bool(root_password) or bool(console_users)
        if root_password is None or console_users is None:
            management_login_text = "could not be fully read"
        elif management_login:
            parts = []
            if root_password:
                parts.append("the root user has a password")
            if console_users:
                parts.append(f"{len(console_users)} IAM users have console passwords ({', '.join(console_users[:10])})")
            management_login_text = "; ".join(parts)
        else:
            management_login_text = "no root password and no IAM user with a console password"

        identity_center_unreadable = any(
            finding.severity == UNVERIFIED and finding.service == IDENTITY_CENTER and finding.check == "instances"
            for finding in self.findings
        )
        if identity_center_unreadable:
            # Instances could not be listed somewhere, so assignments are unknown too.
            self.identity_center_accounts = None
        if not self.identity_center_instances and not identity_center_unreadable:
            self.add(Finding(
                severity=INFO,
                service=ACCOUNT_ACCESS,
                check="lockout risk",
                account_id=self.caller_account_id,
                resource=self.org_id,
                detail="No Identity Center instance, so no account loses Identity Center sign-in on the move.",
            ))
            return

        counts = {
            ACCESS_IDENTITY_CENTER_ONLY: 0,
            ACCESS_IDENTITY_CENTER_RECOVERABLE: 0,
            ACCESS_NOT_IDENTITY_CENTER: 0,
            ACCESS_UNKNOWN: 0,
        }
        at_risk = []
        for account in self.org_accounts:
            account_id = account["Id"]
            if account_id == self.caller_account_id or account.get("Status") != "ACTIVE":
                continue
            joined = account.get("JoinedMethod", "")
            if self.identity_center_accounts is None:
                access = ACCESS_UNKNOWN
                detail = "Identity Center assignments could not be read."
            elif account_id not in self.identity_center_accounts:
                access = ACCESS_NOT_IDENTITY_CENTER
                detail = "No Identity Center permission set is provisioned here. How people sign in can't be read from the management account."
            elif joined == "CREATED" and management_login:
                access = ACCESS_IDENTITY_CENTER_RECOVERABLE
                detail = (
                    "Identity Center sign-in stops on the move. Organizations created this account, so its "
                    "OrganizationAccountAccessRole should trust the old management account, which has a login "
                    "outside Identity Center. Whether the role still exists can't be read from here."
                )
            else:
                access = ACCESS_IDENTITY_CENTER_ONLY
                why = (
                    "It was invited, so it has no OrganizationAccountAccessRole"
                    if joined == "INVITED" else
                    "The old management account has no login outside Identity Center to come back through"
                )
                detail = (
                    f"Identity Center sign-in stops on the move. {why}. Unless an IAM user with a console "
                    "password or the root login works, nobody can get in until Identity Center is rebuilt."
                )
            counts[access] += 1
            if access != ACCESS_NOT_IDENTITY_CENTER:
                at_risk.append(account_id)
            self.add(Finding(
                severity=INFO,
                service=ACCOUNT_ACCESS,
                check="access after move",
                account_id=account_id,
                resource=access,
                detail=f"{account.get('Name', account_id)} (joined: {joined.lower() or 'unknown'}). {detail}",
            ))

        root_text = (
            "could not be read" if root_features is None else
            f"on ({', '.join(root_features)}): member root credentials may have been deleted"
            if root_features else "off"
        )
        self.add(Finding(
            severity=FIX_BEFORE_MOVE if at_risk else INFO,
            service=ACCOUNT_ACCESS,
            check="lockout risk",
            account_id=self.caller_account_id,
            resource=self.org_id,
            detail=(
                f"Identity Center covers accounts that lose that sign-in on the move: "
                f"{counts[ACCESS_IDENTITY_CENTER_ONLY]} with no other way in that radar can see, "
                f"{counts[ACCESS_IDENTITY_CENTER_RECOVERABLE]} reachable through OrganizationAccountAccessRole "
                f"from the old management account, {counts[ACCESS_UNKNOWN]} unknown; "
                f"{counts[ACCESS_NOT_IDENTITY_CENTER]} have no Identity Center assignment. "
                f"Management account login outside Identity Center: {management_login_text}. "
                f"Centralized root access: {root_text}. The scan ran as {caller_kind}. "
                "Whether root password recovery works after an account leaves the org is not verified."
            )[:1500],
            action=(
                "Before any listed account leaves: the customer confirms root email access (or an IAM user "
                "with a console password) for each one, and exports Identity Center users, groups, permission "
                "sets and assignments. Member-account IAM can't be read by radar; check it with Pump's role "
                "in each account."
            ) if at_risk else "",
        ))

    # ── CloudWatch cross-account observability ──

    def check_observability_links(self, region):
        oam = self.client("oam", region)
        sinks = []
        with self.guard("Amazon CloudWatch", "observability sinks", region):
            sinks = list(paginate(oam.list_sinks, "Items"))
        for sink in sinks:
            with self.guard("Amazon CloudWatch", "observability sink policy", region, sink.get("Name", "")):
                policy = oam.get_sink_policy(SinkIdentifier=sink["Arn"]).get("Policy", "")
                keys = org_condition_keys_in(policy)
                if keys or (self.org_id and self.org_id in policy):
                    self.add(Finding(
                        severity=FIX_BEFORE_MOVE,
                        service="Amazon CloudWatch",
                        check="observability sink policy",
                        account_id=self.caller_account_id,
                        region=region,
                        resource=sink.get("Name", sink["Arn"]),
                        detail=f"Sink policy admits source accounts by organization ({', '.join(keys) or self.org_id}).",
                        action="Add the moved account IDs to the sink policy before the move.",
                    ))

        with self.guard("Amazon CloudWatch", "observability links", region):
            links = list(paginate(oam.list_links, "Items"))
            for link in links:
                self.add(Finding(
                    severity=REVIEW,
                    service="Amazon CloudWatch",
                    check="observability link",
                    account_id=self.caller_account_id,
                    region=region,
                    resource=link.get("Arn", ""),
                    detail=f"Shares {', '.join(link.get('ResourceTypes', []))} to sink {link.get('SinkArn', '?')}.",
                    action="Check that the sink's policy doesn't admit this account by organization.",
                ))

    # ── management account policies ──

    def check_management_account_iam(self):
        iam = self.client("iam")
        with self.guard("AWS Identity and Access Management", "policies with org conditions"):
            control_tower_roles = []
            for page in iam_paginate(
                iam.get_account_authorization_details, Filter=["Role", "User", "Group", "LocalManagedPolicy"]
            ):
                for user in page.get("UserDetailList", []):
                    for inline in user.get("UserPolicyList", []):
                        self._flag_policy(
                            self.caller_account_id, "user inline policy",
                            f"{user['UserName']}/{inline['PolicyName']}", inline.get("PolicyDocument"),
                        )
                for group in page.get("GroupDetailList", []):
                    for inline in group.get("GroupPolicyList", []):
                        self._flag_policy(
                            self.caller_account_id, "group inline policy",
                            f"{group['GroupName']}/{inline['PolicyName']}", inline.get("PolicyDocument"),
                        )
                for role in page.get("RoleDetailList", []):
                    if role["RoleName"] in CONTROL_TOWER_ROLE_NAMES:
                        control_tower_roles.append(role["RoleName"])
                    self._flag_policy(
                        self.caller_account_id, "role trust policy", role["RoleName"],
                        role.get("AssumeRolePolicyDocument"),
                    )
                    for inline in role.get("RolePolicyList", []):
                        self._flag_policy(
                            self.caller_account_id, "role inline policy",
                            f"{role['RoleName']}/{inline['PolicyName']}", inline.get("PolicyDocument"),
                        )
                for policy in page.get("Policies", []):
                    default_versions = [
                        version for version in policy.get("PolicyVersionList", []) if version.get("IsDefaultVersion")
                    ]
                    for version in default_versions:
                        self._flag_policy(
                            self.caller_account_id, "managed policy", policy["PolicyName"], version.get("Document"),
                        )
            if control_tower_roles and not self.control_tower_found:
                self.add(Finding(
                    severity=BLOCKER,
                    service=CONTROL_TOWER,
                    check="control tower roles",
                    account_id=self.caller_account_id,
                    resource=", ".join(sorted(control_tower_roles)),
                    detail=(
                        "Control Tower's service roles exist in the management account, so Control Tower is "
                        "(or was) set up. The landing zone itself could not be read."
                    ),
                    action="Route to sales unless the customer confirms Control Tower was decommissioned (CTA onboarding).",
                ))

    def check_management_account_buckets(self):
        s3 = self.client("s3")
        with self.guard("Amazon S3", "bucket policies with org conditions"):
            names = [bucket["Name"] for bucket in s3.list_buckets().get("Buckets", [])]
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                list(pool.map(lambda name: self._scan_bucket_policy(s3, name), names))

    def _scan_bucket_policy(self, s3, name):
        # Per-bucket guard: a bucket that denies GetBucketPolicy gets its own
        # unverified row instead of hiding every other bucket's findings.
        with self.guard("Amazon S3", "bucket policy", resource=name):
            try:
                policy = s3.get_bucket_policy(Bucket=name).get("Policy", "")
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchBucketPolicy", "NoSuchBucket"):
                    return
                raise
            self._flag_policy(self.caller_account_id, "bucket policy", name, policy)

    def _flag_policy(self, account_id, kind, resource, document, region=""):
        if not document:
            return
        keys = org_condition_keys_in(document)
        if not keys:
            return
        self.add(Finding(
            severity=FIX_BEFORE_MOVE,
            service="Amazon S3" if kind == "bucket policy" else "AWS Identity and Access Management",
            check=f"org condition in {kind}",
            account_id=account_id,
            region=region,
            resource=resource,
            detail=f"Uses {', '.join(keys)}; stops matching callers or resources in moved accounts.",
            action="Before the move, add the moved account IDs (or the new org ID) alongside the old org condition.",
        ))

    # ── member accounts ──

    def check_member_accounts(self, regions):
        """Member-account policies through an organization Config aggregator, if there is one."""
        aggregator = None
        aggregator_region = None
        lookup_errors = {}
        for region in regions:
            config = self.client("config", region)
            try:
                aggregators = list(paginate(config.describe_configuration_aggregators, "ConfigurationAggregators"))
            except EndpointConnectionError:
                continue
            except ClientError as error:
                lookup_errors[region] = error.response.get("Error", {}).get("Code", "ClientError")
                continue
            except BotoCoreError as error:
                lookup_errors[region] = type(error).__name__
                continue
            for candidate in aggregators:
                if candidate.get("OrganizationAggregationSource"):
                    aggregator, aggregator_region = candidate, region
                    break
            if aggregator:
                break

        not_scanned = (
            "IAM trust and resource policies with org conditions in member accounts, and CloudWatch "
            "observability sinks in member accounts (RAM shares have their own row)"
        )
        member_ram_shares_found = False
        if not aggregator:
            if lookup_errors:
                errors = ", ".join(f"{region}: {code}" for region, code in sorted(lookup_errors.items()))
                reason = f"Could not look for an organization Config aggregator ({errors})"
            else:
                reason = "No organization Config aggregator found"
            self.add(Finding(
                severity=UNVERIFIED,
                service="Member accounts",
                check="member account policies",
                account_id=self.caller_account_id,
                detail=f"{reason}, so these were not scanned: {not_scanned}."[:1000],
                action="Ask the customer (or the AE checklist) whether member accounts use aws:PrincipalOrgID or org-scoped RAM shares.",
            ))
            self._report_member_ram_shares(member_ram_shares_found)
            return

        name = aggregator["ConfigurationAggregatorName"]
        config = self.client("config", aggregator_region)
        accounts_seen = set()
        query_completed = False
        with self.guard("AWS Config", "aggregator query", aggregator_region):
            for resource_type, kind in (
                ("AWS::IAM::Role", "role policy"),
                ("AWS::IAM::Policy", "managed policy"),
                ("AWS::S3::Bucket", "bucket policy"),
            ):
                expression = (
                    "SELECT accountId, awsRegion, resourceId, resourceName, configuration, "
                    f"supplementaryConfiguration WHERE resourceType = '{resource_type}'"
                )
                results = paginate(
                    config.select_aggregate_resource_config, "Results",
                    Expression=expression, ConfigurationAggregatorName=name, Limit=100,
                )
                for raw in results:
                    item = json.loads(raw)
                    account_id = item.get("accountId", "")
                    accounts_seen.add(account_id)
                    if account_id == self.caller_account_id:
                        # Already scanned directly.
                        continue
                    configuration = item.get("configuration")
                    if resource_type == "AWS::IAM::Policy" and isinstance(configuration, dict):
                        # Config keeps every version; only the default one is in force.
                        configuration = [
                            version for version in configuration.get("policyVersionList", [])
                            if version.get("isDefaultVersion")
                        ]
                    self._flag_policy(
                        account_id, kind, item.get("resourceName") or item.get("resourceId", ""),
                        {
                            "configuration": configuration,
                            "supplementaryConfiguration": item.get("supplementaryConfiguration"),
                        },
                        region=item.get("awsRegion", ""),
                    )
            member_ram_shares_found = self._query_member_ram_shares(config, name)
            query_completed = True

        if not query_completed:
            # The guard already wrote an unverified row with the error.
            self._report_member_ram_shares(member_ram_shares_found)
            return
        missing = sorted(self.org_account_ids - accounts_seen - {self.caller_account_id})
        self.add(Finding(
            severity=INFO,
            service="AWS Config",
            check="member account policies",
            account_id=self.caller_account_id,
            region=aggregator_region,
            resource=name,
            detail=f"Scanned IAM roles, managed policies and bucket policies in {len(accounts_seen)} accounts through aggregator {name}.",
        ))
        if missing:
            self.add(Finding(
                severity=UNVERIFIED,
                service="Member accounts",
                check="member account policies",
                account_id=self.caller_account_id,
                region=aggregator_region,
                resource=name,
                detail=f"{len(missing)} accounts have no IAM or S3 resources in the aggregator: {', '.join(missing[:50])}.",
                action="Check these accounts by hand.",
            ))
        self._report_member_ram_shares(member_ram_shares_found)

    def _query_member_ram_shares(self, config, aggregator_name) -> bool:
        """RAM shares owned by member accounts, as far as Config records them. Returns whether any were found."""
        found = False
        results = paginate(
            config.select_aggregate_resource_config, "Results",
            Expression=(
                "SELECT accountId, awsRegion, resourceId, resourceName, configuration "
                "WHERE resourceType = 'AWS::RAM::ResourceShare'"
            ),
            ConfigurationAggregatorName=aggregator_name, Limit=100,
        )
        for raw in results:
            item = json.loads(raw)
            account_id = item.get("accountId", "")
            if account_id == self.caller_account_id:
                # Already scanned directly.
                continue
            configuration = item.get("configuration") or {}
            status = configuration.get("status", "ACTIVE") if isinstance(configuration, dict) else "ACTIVE"
            if status != "ACTIVE":
                continue
            found = True
            self.add(Finding(
                severity=BLOCKER,
                service=RAM,
                check="member account share",
                account_id=account_id,
                region=item.get("awsRegion", ""),
                resource=item.get("resourceName") or item.get("resourceId", ""),
                detail="RAM share owned by a member account (found through the Config aggregator).",
                action="Route to sales: RAM is on the do-not-touch list (CTA onboarding).",
            ))
        return found

    def _report_member_ram_shares(self, found_any):
        """Say how much of member-account RAM sharing this scan could see."""
        if found_any:
            return
        seen_from_management = (
            "Shares a member account made with the whole org show up above as consumed by the "
            "management account; shares with OUs or with specific accounts don't."
        )
        if self.ram_org_sharing_enabled is False:
            self.add(Finding(
                severity=REVIEW,
                service=RAM,
                check="member account shares",
                account_id=self.caller_account_id,
                detail=(
                    "RAM sharing with the organization is off, so no account can share with the org or an OU. "
                    "Member accounts can still share with specific accounts, which this scan can't see."
                ),
                action="Ask whether member accounts share resources with each other through RAM; if they do, it is CTA onboarding.",
            ))
            return
        self.add(Finding(
            severity=UNVERIFIED,
            service=RAM,
            check="member account shares",
            account_id=self.caller_account_id,
            detail=(
                "RAM sharing with the organization is on (or could not be read), and RAM shares owned by "
                f"member accounts can't be listed from the management account. {seen_from_management}"
            ),
            action=(
                "Ask whether any account (often a networking account) shares subnets, Transit Gateways or "
                "other resources through RAM; if it does, it is CTA onboarding."
            ),
        ))


def _has_login_profile(iam, user_name: str) -> bool:
    """Whether an IAM user has a console password."""
    try:
        iam.get_login_profile(UserName=user_name)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return False
        raise
    return True


def _caller_kind(arn: str) -> str:
    if ":assumed-role/AWSReservedSSO_" in arn:
        return "an Identity Center user"
    if arn.endswith(":root"):
        return "the root user"
    if ":user/" in arn:
        return "an IAM user"
    if ":assumed-role/" in arn:
        return "an assumed IAM role"
    return "an unknown identity"


def _type_counts(types) -> str:
    counts = {}
    for resource_type in types:
        counts[resource_type] = counts.get(resource_type, 0) + 1
    return ", ".join(f"{resource_type} ×{count}" for resource_type, count in sorted(counts.items()))


def verdict(findings: list[Finding]) -> str:
    severities = {finding.severity for finding in findings}
    unverified = sum(1 for finding in findings if finding.severity == UNVERIFIED)
    suffix = f" {unverified} checks could not run; see the unverified rows." if unverified else ""
    if BLOCKER in severities:
        return "CTA onboarding: at least one blocker (route to sales)." + suffix
    unknown = sorted({
        finding.service for finding in findings
        if finding.severity == UNVERIFIED and (
            finding.service in AUTO_CTA_SERVICES
            or (finding.service == "AWS Organizations" and finding.check in ("organization", "accounts"))
        )
    })
    if unknown:
        return (
            f"Undecided: could not confirm {', '.join(unknown)}, any of which means CTA onboarding. "
            "Settle the unverified rows for these (rerun with the missing permissions from the "
            "management account, or ask the customer)." + suffix
        )
    if FIX_BEFORE_MOVE in severities or REVIEW in severities:
        return "Regular onboarding after prep: fix the fix_before_move rows and go through the review rows first." + suffix
    if REENABLE_AFTER_MOVE in severities:
        return "Regular onboarding: re-enable the reenable_after_move rows in the new org." + suffix
    return "Regular onboarding: nothing found that breaks on the move." + suffix


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda finding: (
        SEVERITY_ORDER.index(finding.severity), finding.service, finding.region, finding.resource,
    ))


def _csv_safe(value: str) -> str:
    """Prefix a quote so spreadsheets don't run customer-named values as formulas."""
    if value and value[0] in "=+-@\t\r":
        return "'" + value
    return value


def write_csv(findings: list[Finding], path: str):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLS)
        writer.writeheader()
        for finding in findings:
            writer.writerow({column: _csv_safe(value) for column, value in finding.as_row().items()})


def print_summary(findings: list[Finding]):
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="Organization migration checks")
        for column in ("Severity", "Service", "Check", "Account", "Region", "Resource"):
            table.add_column(column)
        for finding in findings:
            if finding.severity == INFO:
                continue
            table.add_row(
                finding.severity, finding.service, finding.check,
                finding.account_id, finding.region, finding.resource[:60],
            )
        Console().print(table)
    except ImportError:
        for finding in findings:
            if finding.severity != INFO:
                print(f"  [{finding.severity}] {finding.service} – {finding.check}: {finding.resource}")
    print("\n  " + ", ".join(f"{severity}: {count}" for severity, count in counts.items() if count))
    print(f"\n  Verdict: {verdict(findings)}")


def build_session(profile=None):
    botocore_session = botocore.session.get_session()
    botocore_session.set_default_client_config(CLIENT_CONFIG)
    return boto3.Session(botocore_session=botocore_session, profile_name=profile)


def run_checks(profile=None, regions=None, output="org_checks.csv") -> list[Finding]:
    """Run every check, print a summary and write *output*. Returns the sorted findings."""
    try:
        session = build_session(profile)
        identity = session.client("sts").get_caller_identity()
    except NoCredentialsError:
        sys.exit("\n✗ No AWS credentials found.\n")
    except ClientError as error:
        sys.exit(f"\n✗ Auth error: {error}\n")
    print(f"\n✓ Authenticated as: {identity.get('Arn', 'unknown')}")
    print(f"  Account ID : {identity['Account']}")

    findings = sort_findings(OrgChecks(session, regions=regions).run())
    write_csv(findings, output)
    print_summary(findings)
    print(f"\n  ✓ Wrote {len(findings)} findings to {output}")
    return findings


def main():
    parser = argparse.ArgumentParser(description="Organization migration checks (read-only)")
    parser.add_argument("--profile", default=None, help="AWS SSO/named profile")
    parser.add_argument("--region", action="append", default=None,
                        help="Limit regional checks to this region (repeatable; default: all enabled regions)")
    parser.add_argument("--output", metavar="FILE.csv", default="org_checks.csv",
                        help="CSV output path (default: org_checks.csv)")
    args = parser.parse_args()
    run_checks(profile=args.profile, regions=args.region, output=args.output)


if __name__ == "__main__":
    main()
