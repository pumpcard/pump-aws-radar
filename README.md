# pump-aws-radar

A fork of [aws-radar](https://github.com/gomorsmi/aws-radar) that adds a one-command **push** of
your AWS inventory and billing CSVs to Pump's self-serve onboarding endpoint — no standing
cross-account role required.

Everything upstream (`inventory`, `billing`, `diagram`, `run`) works unchanged. The only addition is
`run --upload-token`.

## Install

```bash
pip install pump-aws-radar
```

The console script is `pump-aws-radar`, so it installs alongside upstream `aws-radar` without
colliding.

## Pump onboarding

1. In the Pump app, mint an upload token (this calls `POST /api/v1/estimate/radar/mint`). Pump shows
   you a ready-to-paste command.
2. Run it against the AWS account you want to onboard:

   ```bash
   pump-aws-radar run --all-regions --tags --billing --upload-token <TOKEN>
   ```

   This inventories the account read-only, pulls Cost Explorer billing, uploads both
   `inventory.csv` and `billing.csv` straight to Pump, and also writes the draw.io diagram
   locally. Pass `--no-diagram` to skip the diagram and only upload.
3. Pump detects both files, runs its analysis, and surfaces the findings in the app.

### What leaves your machine

Only the two CSVs. The token carries no AWS credentials and no company id — Pump binds the company
and derives the S3 key server-side, so a token can only ever write its own upload's prefix. Each file
goes to S3 through a short-lived presigned `PUT` URL that Pump mints on demand.

### Pointing at a non-prod backend

The token exchange defaults to `https://api.pump.co`. Override it for local testing:

```bash
pump-aws-radar run --billing --upload-token <TOKEN> --api-base http://localhost:8001
# or
PUMP_API_BASE=http://localhost:8001 pump-aws-radar run --billing --upload-token <TOKEN>
```

## Organization migration checks

Checks what breaks if the organization's accounts move to another AWS Organization.
Run it from the **management account**:

```bash
pump-aws-radar org-checks --profile <management-account-profile>
# or as part of a full run
pump-aws-radar run --all-regions --tags --billing --org-checks --upload-token <TOKEN>
```

It writes `org_checks.csv` (one row per finding: Severity, Service, Check, AccountID, Region,
Resource, Detail, Action) and prints a verdict:

| Found | Verdict |
|---|---|
| any `blocker` | CTA onboarding — route to sales |
| an unverified row for a blocker service | Undecided — rerun with the permissions below, or ask the customer |
| `fix_before_move` or `review` rows | Regular onboarding after prep |
| only `reenable_after_move` rows | Regular onboarding; turn those back on in the new org |

Blockers are the services on the "do not touch, auto CTA" list:

- Control Tower (landing zone, its stack sets or its IAM roles)
- closed or closing accounts in the organization
- IAM Identity Center applications, and users provisioned from an external identity provider (SCIM)
- any active RAM share (owned or consumed), and a RAM delegated administrator
- Application Migration Service (trusted access, delegated administrator, or source servers in the management account)
- EDP or PPA discounts on the bill in the last 12 months (Cost Explorer `RECORD_TYPE`)

Identity Center without SCIM users and RAM shares owned by member accounts can't be confirmed
from the management account, so they come out unverified and the verdict stays undecided until
someone asks the customer.

### Permissions

Everything is read-only. The AWS-managed `ReadOnlyAccess` policy covers every call except
Control Tower's. Add these two actions so the landing zone can be read directly:

```json
{"Effect": "Allow", "Action": ["controltower:ListLandingZones", "controltower:GetLandingZone"], "Resource": "*"}
```

Without them the scan still flags Control Tower from its IAM roles and its `AWSControlTowerBP-*`
stack sets, and adds an unverified row for the landing zone.

Member accounts are only scanned through an organization-wide AWS Config aggregator, if one
exists in the management account. Everything the scan does not cover is listed in a
`not covered` row in the CSV.

## How the push works

`pump_aws_radar/upload.py`:

1. For each role (`inventory`, `billing`), `POST {api_base}/api/v1/estimate/radar/urls` with
   `{"token", "role"}` and receives a presigned S3 `PUT` URL.
2. `PUT`s the corresponding CSV with `Content-Type: text/csv` (the presigned URL signs the
   content-type, so it must match).

## Relationship to upstream

This is a derivative work of [aws-radar](https://github.com/gomorsmi/aws-radar), MIT-licensed, with
upstream copyright preserved in `LICENSE`. The scanning, billing, and diagram code is upstream's; the
Pump push is the fork's addition.
