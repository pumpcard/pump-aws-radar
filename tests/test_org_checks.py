"""Tests for pump_aws_radar.org_checks. AWS is simulated with moto; no network."""

import json
import urllib.parse

import boto3
import pytest
from botocore.exceptions import ClientError

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from pump_aws_radar import org_checks  # noqa: E402
from pump_aws_radar.org_checks import (  # noqa: E402
    BLOCKER,
    FIX_BEFORE_MOVE,
    INFO,
    REENABLE_AFTER_MOVE,
    REVIEW,
    UNVERIFIED,
    Finding,
    OrgChecks,
    org_condition_keys_in,
    verdict,
)

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def _fake_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _by_check(findings, check):
    return [finding for finding in findings if finding.check == check]


# ── pure helpers ──

def test_org_condition_keys_found_in_dict_and_url_encoded_string():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
        }]
    }
    assert org_condition_keys_in(policy) == ["aws:principalorgid"]
    # Config stores IAM documents URL-encoded.
    assert org_condition_keys_in(urllib.parse.quote(json.dumps(policy))) == ["aws:principalorgid"]
    assert org_condition_keys_in({"Statement": []}) == []


def test_verdict_picks_the_most_severe_path():
    blocker = Finding(BLOCKER, "AWS Control Tower", "trusted access")
    fix = Finding(FIX_BEFORE_MOVE, "RAM", "org-scoped share")
    unverified = Finding(UNVERIFIED, "Member accounts", "member account policies")
    assert verdict([fix, blocker]).startswith("CTA onboarding")
    assert verdict([fix]).startswith("Regular onboarding after prep")
    assert verdict([Finding(INFO, "x", "y")]).startswith("Regular onboarding: nothing found")
    assert verdict([Finding(REENABLE_AFTER_MOVE, "x", "y")]).startswith("Regular onboarding: re-enable")
    assert "1 checks could not run" in verdict([fix, unverified])


# ── against moto ──

@mock_aws
def test_standalone_account_reports_no_org():
    findings = OrgChecks(boto3.Session(), regions=[REGION]).run()
    assert [finding.check for finding in findings] == ["organization"]
    assert findings[0].severity == INFO
    assert "not in an AWS Organization" in findings[0].detail


@mock_aws
def test_management_account_findings():
    session = boto3.Session()
    organizations = session.client("organizations", region_name=REGION)
    org_id = organizations.create_organization(FeatureSet="ALL")["Organization"]["Id"]
    member_id = organizations.create_account(AccountName="member", Email="member@example.com")[
        "CreateAccountStatus"]["AccountId"]
    organizations.enable_aws_service_access(ServicePrincipal="controltower.amazonaws.com")
    organizations.enable_aws_service_access(ServicePrincipal="guardduty.amazonaws.com")
    organizations.register_delegated_administrator(AccountId=member_id, ServicePrincipal="guardduty.amazonaws.com")

    iam = session.client("iam")
    iam.create_role(
        RoleName="CrossAccountMetrics",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": org_id}},
            }],
        }),
    )
    iam.create_role(
        RoleName="Plain",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )

    s3 = session.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="org-logs")
    s3.put_bucket_policy(Bucket="org-logs", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::org-logs/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": org_id}},
        }],
    }))
    s3.create_bucket(Bucket="no-policy")

    findings = OrgChecks(session, regions=[REGION]).run()

    trusted = {finding.resource: finding for finding in _by_check(findings, "trusted access")}
    assert trusted["controltower.amazonaws.com"].severity == BLOCKER
    assert trusted["guardduty.amazonaws.com"].severity == REENABLE_AFTER_MOVE

    delegated = _by_check(findings, "delegated administrator")
    assert [(finding.account_id, finding.resource) for finding in delegated] == [
        (member_id, "guardduty.amazonaws.com")
    ]

    role_findings = _by_check(findings, "org condition in role trust policy")
    assert [finding.resource for finding in role_findings] == ["CrossAccountMetrics"]
    assert role_findings[0].severity == FIX_BEFORE_MOVE

    bucket_findings = _by_check(findings, "org condition in bucket policy")
    assert [finding.resource for finding in bucket_findings] == ["org-logs"]

    # No organization Config aggregator in this account.
    member = _by_check(findings, "member account policies")
    assert member and member[0].severity == UNVERIFIED

    assert verdict(findings).startswith("CTA onboarding")


@mock_aws
def test_org_trail_and_foreign_bucket():
    session = boto3.Session()
    session.client("organizations", region_name=REGION).create_organization(FeatureSet="ALL")
    s3 = session.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="trail-bucket")
    cloudtrail = session.client("cloudtrail", region_name=REGION)
    cloudtrail.create_trail(Name="org-trail", S3BucketName="trail-bucket", IsOrganizationTrail=True)

    checks = OrgChecks(session, regions=[REGION])
    # Pretend the bucket belongs to another account (e.g. a log archive or a vendor).
    checks._bucket_names_listed = True
    checks._bucket_names = set()
    findings = checks.run()

    assert [finding.resource for finding in _by_check(findings, "organization trail")] == ["org-trail"]
    destination = _by_check(findings, "trail destination")
    assert destination and destination[0].severity == REVIEW
    assert "trail-bucket" in destination[0].detail


# ── StackSets (moto omits AutoDeployment, so a hand-written client) ──

class _FakeCloudFormation:
    STACK_SETS = {
        "deletes": {"PermissionModel": "SERVICE_MANAGED", "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": False}},
        "retains": {"PermissionModel": "SERVICE_MANAGED", "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": True}},
        "manual": {"PermissionModel": "SERVICE_MANAGED", "AutoDeployment": {"Enabled": False}},
        "self-managed": {"PermissionModel": "SELF_MANAGED"},
        "AWSControlTowerBP-BASELINE": {"PermissionModel": "SELF_MANAGED"},
    }

    def list_stack_sets(self, Status, CallAs, NextToken=None):
        return {"Summaries": [
            {"StackSetName": name, "PermissionModel": stack_set["PermissionModel"]}
            for name, stack_set in self.STACK_SETS.items()
        ]}

    def list_stack_instances(self, StackSetName, CallAs, NextToken=None):
        return {"Summaries": [{"Account": "222222222222"}, {"Account": "333333333333"}]}

    def describe_stack_set(self, StackSetName, CallAs):
        return {"StackSet": self.STACK_SETS[StackSetName]}


def _stack_set_findings(monkeypatch, control_tower_found):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: _FakeCloudFormation())
    checks.caller_account_id = "111111111111"
    checks.is_management_account = True
    checks.control_tower_found = control_tower_found
    checks.check_stack_sets(REGION)
    return {finding.resource: finding for finding in checks.findings}


def test_stack_sets_by_auto_deployment(monkeypatch):
    by_name = _stack_set_findings(monkeypatch, control_tower_found=True)
    assert by_name["deletes"].severity == FIX_BEFORE_MOVE
    assert "DELETED" in by_name["deletes"].detail
    assert "2 instances in 2 accounts" in by_name["deletes"].detail
    assert by_name["retains"].severity == REENABLE_AFTER_MOVE
    assert by_name["manual"].severity == REENABLE_AFTER_MOVE
    assert "DELETED" not in by_name["manual"].detail
    assert "RetainStacksOnAccountRemoval=true" not in by_name["manual"].action
    assert by_name["self-managed"].severity == INFO
    assert by_name["AWSControlTowerBP-BASELINE"].severity == INFO


def test_control_tower_stack_set_is_a_blocker_when_landing_zone_unreadable(monkeypatch):
    by_name = _stack_set_findings(monkeypatch, control_tower_found=False)
    assert by_name["AWSControlTowerBP-BASELINE"].severity == BLOCKER


class _FakeControlTower:
    ARN = "arn:aws:controltower:us-west-2:111111111111:landingzone/LZ1"

    def __init__(self, landing_zones):
        self._landing_zones = landing_zones
        self.regions_asked = []

    def list_landing_zones(self, nextToken=None):
        return {"landingZones": [{"arn": arn} for arn in self._landing_zones]}

    def get_landing_zone(self, landingZoneIdentifier):
        return {"landingZone": {"version": "3.3", "status": "ACTIVE", "driftStatus": {"status": "IN_SYNC"}}}


def test_control_tower_landing_zone_is_a_blocker_without_trusted_access(monkeypatch):
    control_tower = _FakeControlTower([_FakeControlTower.ARN])
    regions = []

    def client(service, region="us-east-1"):
        regions.append(region)
        return control_tower

    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", client)
    checks.check_control_tower()

    [finding] = checks.findings
    assert finding.severity == BLOCKER
    assert finding.region == "us-west-2"
    assert "status ACTIVE" in finding.detail
    # Details are read from the landing zone's home region.
    assert regions == ["us-east-1", "us-west-2"]
    assert verdict(checks.findings).startswith("CTA onboarding")


def test_no_landing_zone_no_finding(monkeypatch):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: _FakeControlTower([]))
    checks.check_control_tower()
    assert checks.findings == []


# ── Identity Center (moto has no ListApplications) ──

class _FakeSsoAdmin:
    def list_instances(self, NextToken=None):
        return {"Instances": [{
            "InstanceArn": "arn:aws:sso:::instance/ssoins-1", "IdentityStoreId": "d-1",
            "OwnerAccountId": "111111111111",
        }]}

    def list_permission_sets(self, InstanceArn, NextToken=None):
        return {"PermissionSets": ["ps-1", "ps-2"]}

    def list_applications(self, InstanceArn, NextToken=None):
        return {"Applications": [
            {"Name": "Corp VPN", "ApplicationProviderArn": "arn:aws:sso::aws:applicationProvider/custom"},
            {"Name": "TEAM IDC APP", "ApplicationProviderArn": "arn:aws:sso::aws:applicationProvider/custom"},
            {"Name": "Data Team Portal", "ApplicationProviderArn": "arn:aws:sso::aws:applicationProvider/custom"},
        ]}


class _FakeIdentityStore:
    def list_users(self, IdentityStoreId, NextToken=None):
        # SCIM users only on the second page.
        if NextToken is None:
            return {"Users": [{"UserName": "break-glass"}], "NextToken": "page-2"}
        return {"Users": [{"UserName": "a", "ExternalIds": [{"Issuer": "https://scim.okta.com", "Id": "1"}]}]}


def test_identity_center(monkeypatch):
    clients = {"sso-admin": _FakeSsoAdmin(), "identitystore": _FakeIdentityStore()}
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: clients[service])
    checks.check_identity_center(REGION)

    by_check = {}
    for finding in checks.findings:
        by_check.setdefault(finding.check, []).append(finding)
    assert "2 permission sets" in by_check["instance"][0].detail
    applications = {finding.resource: finding for finding in by_check["application"]}
    assert set(applications) == {"Corp VPN", "TEAM IDC APP", "Data Team Portal"}
    assert "Looks like TEAM" in applications["TEAM IDC APP"].detail
    assert "Looks like TEAM" not in applications["Corp VPN"].detail
    assert "Looks like TEAM" not in applications["Data Team Portal"].detail
    assert "scim.okta.com" in by_check["external identity provider"][0].detail
    # Applications and an external IdP are on the do-not-touch list.
    assert by_check["instance"][0].severity == FIX_BEFORE_MOVE
    assert all(finding.severity == BLOCKER for finding in by_check["application"])
    assert by_check["external identity provider"][0].severity == BLOCKER


class _LocalUsersIdentityStore:
    def list_users(self, IdentityStoreId, NextToken=None):
        return {"Users": [{"UserName": "admin"}]}


def test_identity_source_unknown_without_scim(monkeypatch):
    clients = {"sso-admin": _FakeSsoAdmin(), "identitystore": _LocalUsersIdentityStore()}
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: clients[service])
    checks.check_identity_center(REGION)
    [source] = [finding for finding in checks.findings if finding.check == "identity source"]
    assert source.severity == UNVERIFIED
    assert not [finding for finding in checks.findings if finding.check == "external identity provider"]


class _EmptyIdentityStore:
    def list_users(self, IdentityStoreId, NextToken=None):
        return {"Users": []}


def test_identity_store_without_users_is_not_undecided(monkeypatch):
    clients = {"sso-admin": _FakeSsoAdmin(), "identitystore": _EmptyIdentityStore()}
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: clients[service])
    checks.check_identity_center(REGION)
    [source] = _by_check(checks.findings, "identity source")
    assert source.severity == INFO


def test_identity_source_unknown_leaves_verdict_undecided():
    findings = [
        Finding(FIX_BEFORE_MOVE, "AWS IAM Identity Center", "instance"),
        Finding(UNVERIFIED, "AWS IAM Identity Center", "identity source"),
    ]
    assert verdict(findings).startswith("Undecided: could not confirm AWS IAM Identity Center")


# ── RAM (moto has no ListPrincipals or OTHER-ACCOUNTS, so a hand-written client) ──

ORG_ARN = "arn:aws:organizations::111111111111:organization/o-abc"
OU_ARN = "arn:aws:organizations::111111111111:ou/o-abc/ou-1"


class _FakeRam:
    def __init__(self, owned, consumed, principals, resources):
        self._shares = {"SELF": owned, "OTHER-ACCOUNTS": consumed}
        self._principals = principals
        self._resources = resources

    def get_resource_shares(self, resourceOwner, resourceShareStatus=None, nextToken=None):
        return {"resourceShares": self._shares[resourceOwner]}

    def list_principals(self, resourceOwner, resourceShareArns, nextToken=None):
        return {"principals": [{"id": principal} for principal in self._principals[resourceShareArns[0]]]}

    def list_resources(self, resourceOwner, resourceShareArns, nextToken=None):
        return {"resources": [{"type": kind} for kind in self._resources[resourceShareArns[0]]]}


def test_ram_shares(monkeypatch):
    ram = _FakeRam(
        owned=[
            {"resourceShareArn": "s-org", "name": "subnets", "allowExternalPrincipals": False},
            {"resourceShareArn": "s-ou", "name": "licenses", "allowExternalPrincipals": False},
            {"resourceShareArn": "s-acct", "name": "by-account", "allowExternalPrincipals": False},
            {"resourceShareArn": "s-ext", "name": "external-ok", "allowExternalPrincipals": True},
        ],
        consumed=[{"resourceShareArn": "s-in", "name": "tgw", "owningAccountId": "222222222222"}],
        principals={
            "s-org": [ORG_ARN],
            "s-ou": [OU_ARN],
            "s-acct": ["333333333333"],
            "s-ext": ["444444444444"],
        },
        resources={
            "s-org": ["ec2:Subnet", "ec2:Subnet"],
            "s-ou": ["license-manager:LicenseConfiguration"],
            "s-acct": ["ec2:PrefixList"],
            "s-ext": ["ec2:PrefixList"],
            "s-in": ["ec2:TransitGateway"],
        },
    )
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: ram)
    checks.check_ram_shares(REGION)

    by_resource = {finding.resource: finding for finding in checks.findings}
    # RAM is on the do-not-touch list: every active share is a blocker.
    assert set(by_resource) == {"subnets", "licenses", "by-account", "external-ok", "tgw"}
    assert {finding.severity for finding in checks.findings} == {BLOCKER}
    assert by_resource["subnets"].check == "org-scoped share"
    assert "ec2:Subnet ×2" in by_resource["subnets"].detail
    assert "can't create new ones" in by_resource["subnets"].detail
    assert "lose access" in by_resource["licenses"].detail
    assert by_resource["by-account"].check == "account share"
    assert "External principals are off" in by_resource["by-account"].detail
    assert "External principals are off" not in by_resource["external-ok"].detail
    assert "222222222222" in by_resource["tgw"].detail
    assert "networking" in by_resource["tgw"].detail


class _FakeConfig:
    def __init__(self, results):
        self._results = results

    def select_aggregate_resource_config(self, Expression, ConfigurationAggregatorName, Limit, NextToken=None):
        assert "AWS::RAM::ResourceShare" in Expression
        return {"Results": [json.dumps(result) for result in self._results]}


def test_member_ram_shares_from_aggregator():
    checks = OrgChecks(session=None, regions=[REGION])
    checks.caller_account_id = "111111111111"
    found = checks._query_member_ram_shares(_FakeConfig([
        {"accountId": "222222222222", "awsRegion": REGION, "resourceName": "net-share", "configuration": {"status": "ACTIVE"}},
        {"accountId": "222222222222", "awsRegion": REGION, "resourceName": "old", "configuration": {"status": "DELETED"}},
        {"accountId": "111111111111", "awsRegion": REGION, "resourceName": "mine", "configuration": {"status": "ACTIVE"}},
    ]), "org-aggregator")
    assert found
    assert [(finding.severity, finding.account_id, finding.resource) for finding in checks.findings] == [
        (BLOCKER, "222222222222", "net-share"),
    ]


@pytest.mark.parametrize(("org_sharing", "severity"), [(False, REVIEW), (True, UNVERIFIED), (None, UNVERIFIED)])
def test_member_ram_shares_unseen(org_sharing, severity):
    checks = OrgChecks(session=None, regions=[REGION])
    checks.ram_org_sharing_enabled = org_sharing
    checks._report_member_ram_shares(found_any=False)
    [finding] = checks.findings
    assert finding.severity == severity
    assert finding.service == "AWS Resource Access Manager"
    if severity == UNVERIFIED:
        assert verdict(checks.findings).startswith("Undecided")


# ── closed accounts, delegated admins (hand-written Organizations client) ──

class _FakeOrganizations:
    def describe_organization(self):
        return {"Organization": {"Id": "o-abc", "MasterAccountId": "111111111111"}}

    def list_accounts(self, NextToken=None):
        return {"Accounts": [
            {"Id": "111111111111", "Name": "management", "Status": "ACTIVE", "State": "ACTIVE"},
            {"Id": "222222222222", "Name": "old-sandbox", "Status": "SUSPENDED", "State": "CLOSED"},
            {"Id": "333333333333", "Name": "closing", "Status": "PENDING_CLOSURE"},
        ]}

    def list_delegated_administrators(self, NextToken=None):
        return {"DelegatedAdministrators": [{"Id": "444444444444", "Name": "migration"}]}

    def list_delegated_services_for_account(self, AccountId, NextToken=None):
        return {"DelegatedServices": [
            {"ServicePrincipal": "mgn.amazonaws.com"},
            {"ServicePrincipal": "guardduty.amazonaws.com"},
        ]}


def test_closed_accounts_are_blockers(monkeypatch):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: _FakeOrganizations())
    checks.caller_account_id = "111111111111"
    checks.check_organization()
    closed = {finding.account_id: finding for finding in _by_check(checks.findings, "closed account")}
    assert set(closed) == {"222222222222", "333333333333"}
    assert {finding.severity for finding in closed.values()} == {BLOCKER}
    assert "closed" in closed["222222222222"].detail
    assert "pending closure" in closed["333333333333"].detail
    assert checks.org_account_ids == {"111111111111"}


def test_application_migration_delegated_admin_is_a_blocker(monkeypatch):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: _FakeOrganizations())
    checks.check_delegated_administrators()
    by_principal = {finding.resource: finding for finding in checks.findings}
    assert by_principal["mgn.amazonaws.com"].severity == BLOCKER
    assert by_principal["mgn.amazonaws.com"].service == "AWS Application Migration Service"
    assert by_principal["guardduty.amazonaws.com"].severity == FIX_BEFORE_MOVE


# ── Application Migration Service ──

class _FakeMgn:
    def __init__(self, servers=None, uninitialized=False):
        self._servers = servers or []
        self._uninitialized = uninitialized

    def describe_source_servers(self, filters, nextToken=None):
        if self._uninitialized:
            raise ClientError({"Error": {"Code": "UninitializedAccountException", "Message": ""}}, "DescribeSourceServers")
        assert filters == {"isArchived": False}
        return {"items": self._servers}


def test_application_migration_source_servers(monkeypatch):
    mgn = _FakeMgn([{"lifeCycle": {"state": "READY_FOR_TEST"}}, {"lifeCycle": {"state": "CUTOVER"}}])
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: mgn)
    checks.check_application_migration(REGION)
    [finding] = checks.findings
    assert finding.severity == BLOCKER
    assert "2 source servers" in finding.detail
    assert "READY_FOR_TEST ×1" in finding.detail


@pytest.mark.parametrize("mgn", [_FakeMgn(), _FakeMgn(uninitialized=True)])
def test_application_migration_not_in_use(monkeypatch, mgn):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: mgn)
    checks.check_application_migration(REGION)
    assert checks.findings == []


# ── EDP / PPA ──

class _FakeCostExplorer:
    def __init__(self, record_types):
        self._record_types = record_types
        self.calls = []

    def get_dimension_values(self, TimePeriod, Dimension, NextPageToken=None):
        self.calls.append((TimePeriod, Dimension))
        return {"DimensionValues": [{"Value": value} for value in self._record_types]}


@pytest.mark.parametrize(("record_types", "severity", "resource"), [
    (["Usage", "Tax", "Enterprise Discount Program Discount"], BLOCKER, "EDP"),
    (["Usage", "Private Rate Card Discount", "Enterprise Discount Program Discount"], BLOCKER, "EDP, PPA"),
    (["Usage", "Credit", "Solution Provider Program Discount"], INFO, ""),
])
def test_private_pricing(monkeypatch, record_types, severity, resource):
    cost_explorer = _FakeCostExplorer(record_types)
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: cost_explorer)
    checks.check_private_pricing()
    [finding] = checks.findings
    assert finding.severity == severity
    assert finding.resource == resource
    assert cost_explorer.calls[0][1] == "RECORD_TYPE"


def test_private_pricing_unreadable_leaves_verdict_undecided(monkeypatch):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: _DeniedClient(service))
    checks.check_private_pricing()
    [finding] = checks.findings
    assert finding.severity == UNVERIFIED
    assert verdict(checks.findings).startswith("Undecided: could not confirm EDP / PPA")


# ── failure handling ──

class _DeniedClient:
    """A client whose every call fails with AccessDenied."""

    def __init__(self, service):
        self.service = service

    def __getattr__(self, name):
        def call(**kwargs):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": f"{self.service}:{name}"}}, name)
        return call


def test_access_denied_becomes_unverified_row(monkeypatch):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: _DeniedClient(service))
    checks.caller_account_id = "111111111111"
    checks.is_management_account = True

    checks.check_trusted_access()
    checks.check_ram_shares(REGION)

    assert {finding.severity for finding in checks.findings} == {UNVERIFIED}
    assert {finding.check for finding in checks.findings} == {"trusted access", "owned shares", "consumed shares"}
    assert all("AccessDenied" in finding.detail for finding in checks.findings)


class _PartlyDeniedS3:
    POLICIES = {
        "a-org": json.dumps({"Statement": [{"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}]}),
    }

    def list_buckets(self):
        return {"Buckets": [{"Name": "a-org"}, {"Name": "b-denied"}, {"Name": "c-none"}]}

    def get_bucket_policy(self, Bucket):
        if Bucket == "b-denied":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetBucketPolicy")
        if Bucket == "c-none":
            raise ClientError({"Error": {"Code": "NoSuchBucketPolicy", "Message": ""}}, "GetBucketPolicy")
        return {"Policy": self.POLICIES[Bucket]}


def test_one_unreadable_bucket_does_not_hide_the_others(monkeypatch):
    checks = OrgChecks(session=None, regions=[REGION])
    monkeypatch.setattr(checks, "client", lambda service, region=None: _PartlyDeniedS3())
    checks.check_management_account_buckets()
    by_resource = {finding.resource: finding for finding in checks.findings}
    assert set(by_resource) == {"a-org", "b-denied"}
    assert by_resource["a-org"].severity == FIX_BEFORE_MOVE
    assert by_resource["b-denied"].severity == UNVERIFIED


def test_verdict_undecided_when_control_tower_unreadable():
    findings = [
        Finding(FIX_BEFORE_MOVE, "RAM", "org-scoped share"),
        Finding(UNVERIFIED, "AWS Control Tower", "landing zone", detail="AccessDeniedException"),
    ]
    assert verdict(findings).startswith("Undecided")


def test_csv_round_trip(tmp_path):
    path = tmp_path / "org_checks.csv"
    org_checks.write_csv([Finding(BLOCKER, "AWS Control Tower", "trusted access", "1", "", "ct", "d", "a")], str(path))
    lines = path.read_text().splitlines()
    assert lines[0] == ",".join(org_checks.COLS)
    assert lines[1] == "blocker,AWS Control Tower,trusted access,1,,ct,d,a"


def test_csv_neutralizes_formulas(tmp_path):
    path = tmp_path / "org_checks.csv"
    org_checks.write_csv([Finding(REVIEW, "RAM", "share", resource="=HYPERLINK(1)")], str(path))
    assert "'=HYPERLINK(1)" in path.read_text()
