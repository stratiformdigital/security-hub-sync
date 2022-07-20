import AWS from "aws-sdk";
import { Octokit } from "octokit";
import _ from "lodash";
const findingIdRegex = /(?<=\nFinding Id: ).*/g;

export class SechubGithubSync {
  constructor(options) {
    this.severity = options.severity || ["MEDIUM", "HIGH", "CRITICAL"];
    this.octokitRepoParams = {
      owner: options.repository.split("/")[0],
      repo: options.repository.split("/")[1],
    };
    this.octokit = new Octokit({ auth: options.auth });
    this.region = options.region;
    this.accountNickname = options.accountNickname || null;
  }

  async sync() {
    const findings = await this.getAllActiveFindings();
    var issues = await this.getAllIssues();
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
    const securityhub = new AWS.SecurityHub({ region: this.region });
    // prettier-ignore
    for await (const lf of (async function * () {
      let NextToken = EMPTY;
      while (NextToken || NextToken === EMPTY) {
        const functions = await securityhub
          .getFindings({
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
          .promise();
        yield* functions.Findings;
        NextToken = functions.NextToken;
      }
    })()) {
      res.push(lf);
    }
    return res;
  }

  async getAllIssues() {
    let issues = [];
    for await (const response of this.octokit.paginate.iterator(
      this.octokit.rest.issues.listForRepo,
      {
        ...this.octokitRepoParams,
        state: "all",
        labels: ["security-hub", this.region],
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
        finding.Severity.Label,
        this.accountNickname || finding.AwsAccountId,
      ],
      body: `**************************************************************
__This issue was generated from Security Hub data and is managed through automation.__
Please do not edit the title or body of this issue, or remove the security-hub tag.  All other edits/comments are welcome.
Finding Id: ${finding.Id}
**************************************************************


## Type of Issue:

- [x] Security Hub Finding

## Title:

${finding.Title}

## Id:

${finding.Id}
(You may use this ID to lookup this finding's details in Security Hub)

## Description

${finding.Description}

## Remediation

${finding.ProductFields.RecommendationUrl}

## AC:

- The security hub finding is resolved or suppressed, indicated by a Workflow Status of Resolved or Suppressed.
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
    var findingsIds = _.map(findings, "Id");
    // Search for open issues that do not have a corresponding active SH finding.
    for (let i = 0; i < issues.length; i++) {
      let issue = issues[i];
      if (issue.state != "open") continue; // We only care about open issues here.
      let issueId = issue.body.match(findingIdRegex);
      if (issueId && findingsIds.includes(issueId[0])) {
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
        let issueId = issue.body.match(findingIdRegex);
        if (finding.Id == issueId) {
          hit = true;
          console.log(
            `Finding ${finding.Id}:  Issue ${issue.number} found for finding.  Checking it's up to date...`
          );
          await this.updateIssueIfItsDrifted(finding, issue);
          break;
        }
      }
      if (!hit) {
        console.log(
          `Finding ${finding.Id}:  No issue found for finding.  Creating issue...`
        );
        await this.createNewGitHubIssue(finding);
      }
    }
  }
}
