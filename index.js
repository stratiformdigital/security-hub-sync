import {
  SecurityHubClient,
  GetFindingsCommand,
} from "@aws-sdk/client-securityhub";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { Octokit } from "octokit";
import _ from "lodash";
const findingTitleRegex = /(?<=\nFinding Title: ).*/g;

export class SechubGithubSync {
  constructor(options) {
    this.severity = options.severity || ["HIGH", "CRITICAL"];
    this.octokitRepoParams = {
      owner: options.repository.split("/")[0],
      repo: options.repository.split("/")[1],
    };
    this.octokit = new Octokit({ auth: options.auth });
    this.region = options.region || "us-east-1";
    this.accountNickname = options.accountNickname || null;
  }

  async sync() {
    if (!this.accountNickname) {
      const stsClient = new STSClient({ region: this.region });
      this.accountNickname = (
        await stsClient.send(new GetCallerIdentityCommand())
      ).Account;
    }
    const findings = await this.getAllActiveFindings();
    const issues = await this.getAllIssues();
    await this.closeIssuesWithoutAnActiveFinding(findings, issues);
    await this.createOrUpdateIssuesBasedOnFindings(findings, issues);
  }

  async getAllActiveFindings() {
    const EMPTY = Symbol("empty");
    const res = [];
    let severityLabels = [];
    this.severity.forEach(function (label) {
      severityLabels.push({
        Comparison: "EQUALS",
        Value: label,
      });
    });
    const client = new SecurityHubClient({ region: this.region });
    for await (const lf of (async function* () {
      let NextToken = EMPTY;
      while (NextToken || NextToken === EMPTY) {
        const functions = await client.send(
          new GetFindingsCommand({
            Filters: {
              RecordState: [
                {
                  Comparison: "EQUALS",
                  Value: "ACTIVE",
                },
              ],
              WorkflowStatus: [
                {
                  Comparison: "EQUALS",
                  Value: "NEW",
                },
                {
                  Comparison: "EQUALS",
                  Value: "NOTIFIED",
                },
              ],
              SeverityLabel: severityLabels,
            },
            MaxResults: 100,
            NextToken: NextToken !== EMPTY ? NextToken : undefined,
          })
        );
        yield* functions.Findings;
        NextToken = functions.NextToken;
      }
    })()) {
      res.push(lf);
    }
    var formattedFindings = _.map(res, function (finding) {
      return {
        Title: finding.Title,
        Description: finding.Description,
        Severity: finding.Severity.Label,
        Region: finding.Region,
        Recommendation: finding.Remediation.Recommendation,
      };
    });
    var uniqueFindings = _.uniqBy(formattedFindings, "Title");
    return uniqueFindings;
  }

  async getAllIssues() {
    let issues = [];
    for await (const response of this.octokit.paginate.iterator(
      this.octokit.rest.issues.listForRepo,
      {
        ...this.octokitRepoParams,
        state: "all",
        labels: ["security-hub", this.region, this.accountNickname],
      }
    )) {
      issues.push(...response.data);
    }
    return issues;
  }

  issueParamsForFinding(finding) {
    return {
      title: `SecurityHub Finding - ${finding.Title}`,
      state: "open",
      labels: [
        "security-hub",
        this.region,
        finding.Severity,
        this.accountNickname,
      ],
      body: `**************************************************************
__This issue was generated from Security Hub data and is managed through automation.__
Please do not edit the title or body of this issue, or remove the security-hub tag.  All other edits/comments are welcome.
Finding Title: ${finding.Title}
**************************************************************


## Type of Issue:

- [x] Security Hub Finding

## Title:

${finding.Title}

## Description

${finding.Description}

## Remediation

${finding.Recommendation.Url}
${finding.Recommendation.Text}

## AC:

- All findings of this type are resolved or suppressed, indicated by a Workflow Status of Resolved or Suppressed.  (Note:  this ticket will automatically close when the AC is met.)
      `,
    };
  }

  async createNewGitHubIssue(finding) {
    await this.octokit.rest.issues.create({
      ...this.octokitRepoParams,
      ...this.issueParamsForFinding(finding),
    });
    // Due to github secondary rate limiting, we will take a 5s pause after creating issues.
    // See:  https://docs.github.com/en/rest/overview/resources-in-the-rest-api#secondary-rate-limits
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }

  async updateIssueIfItsDrifted(finding, issue) {
    let issueParams = this.issueParamsForFinding(finding);
    let issueLabels = [];
    issue.labels.forEach(function (label) {
      issueLabels.push(label.name);
    });
    if (
      issue.title != issueParams.title ||
      issue.state != issueParams.state ||
      issue.body != issueParams.body ||
      !issueParams.labels.every((v) => issueLabels.includes(v))
    ) {
      console.log(`Issue ${issue.number}:  drift detected.  Updating issue...`);
      await this.octokit.rest.issues.update({
        ...this.octokitRepoParams,
        ...issueParams,
        issue_number: issue.number,
      });
    } else {
      console.log(
        `Issue ${issue.number}:  Issue is up to date.  Doing nothing...`
      );
    }
  }

  async closeIssuesWithoutAnActiveFinding(findings, issues) {
    console.log(
      `******** Discovering and closing any open GitHub Issues without an underlying, active Security Hub finding. ********`
    );

    // Store all finding ids in an array
    var findingsTitles = _.map(findings, "Title");
    // Search for open issues that do not have a corresponding active SH finding.
    for (let i = 0; i < issues.length; i++) {
      let issue = issues[i];
      if (issue.state != "open") continue; // We only care about open issues here.
      let issueTitle = issue.body.match(findingTitleRegex);
      if (issueTitle && findingsTitles.includes(issueTitle[0])) {
        console.log(
          `Issue ${issue.number}:  Underlying finding found.  Doing nothing...`
        );
      } else {
        console.log(
          `Issue ${issue.number}:  No underlying finding found.  Closing issue...`
        );
        await this.octokit.rest.issues.update({
          ...this.octokitRepoParams,
          issue_number: issue.number,
          state: "closed",
        });
      }
    }
  }

  async createOrUpdateIssuesBasedOnFindings(findings, issues) {
    console.log(
      `******** Creating or updating GitHub Issues based on Security Hub findings. ********`
    );
    // Search for active SH findings that don't have an open issue
    for (let i = 0; i < findings.length; i++) {
      var finding = findings[i];
      let hit = false;
      for (let j = 0; j < issues.length; j++) {
        var issue = issues[j];
        let issueTitle = issue.body.match(findingTitleRegex);
        if (finding.Title == issueTitle) {
          hit = true;
          console.log(
            `Finding ${finding.Title}:  Issue ${issue.number} found for finding.  Checking it's up to date...`
          );
          await this.updateIssueIfItsDrifted(finding, issue);
          break;
        }
      }
      if (!hit) {
        console.log(
          `Finding ${finding.Title}:  No issue found for finding.  Creating issue...`
        );
        await this.createNewGitHubIssue(finding);
      }
    }
  }
}
