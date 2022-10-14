import { SechubGithubSync } from "../index.js";
import {
  EC2Client,
  CreateSecurityGroupCommand,
  AuthorizeSecurityGroupIngressCommand,
} from "@aws-sdk/client-ec2";
import {
  SecurityHubClient,
  GetFindingsCommand,
} from "@aws-sdk/client-securityhub";
import { Octokit } from "octokit";
import _ from "lodash";
const region = "us-east-1";
const accountNickname =
  process.env.ISSUE_LABEL || process.env.USER || "test-issues";
const octokitRepoParams = {
  owner: process.env.GITHUB_REPOSITORY.split("/")[0],
  repo: process.env.GITHUB_REPOSITORY.split("/")[1],
};
async function ensureThereAreFindingsToTestAgainst() {
  const secgroups = [
    `security-hub-sync-test-sg-one`,
    `security-hub-sync-test-sg-two`,
  ];
  const ec2Client = new EC2Client({
    region: region,
  });
  for (var i = 0; i < secgroups.length; i++) {
    try {
      await ec2Client.send(
        new CreateSecurityGroupCommand({
          Description:
            "DO NOT USE.  This is made to trip Sec Hub Findings as part of a test workflow.",
          GroupName: secgroups[i],
        })
      );
    } catch (error) {
      if (error.Code == "InvalidGroup.Duplicate") {
        console.log("Group already exists");
      } else {
        throw error;
      }
    }
    try {
      await ec2Client.send(
        new AuthorizeSecurityGroupIngressCommand({
          GroupName: secgroups[i],
          CidrIp: "0.0.0.0/0",
          FromPort: 8080,
          ToPort: 8080,
          IpProtocol: "tcp",
        })
      );
    } catch (error) {
      if (error.Code == "InvalidPermission.Duplicate") {
        console.log("SG Rule already exists.");
      } else {
        throw error;
      }
    }
  }
  const sechubClient = new SecurityHubClient({
    region: region,
  });
  while (true) {
    var findings = await sechubClient.send(
      new GetFindingsCommand({
        Filters: {
          Title: [
            {
              Comparison: "EQUALS",
              Value:
                "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
            },
          ],
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
        },
      })
    );
    if (findings.Findings.length >= 2) {
      break;
    } else {
      console.log(
        "Waiting for there to be at least two Findings of the same type to test against..."
      );
      await new Promise((r) => setTimeout(r, 10000));
    }
  }
}
var octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

async function runSecHubSync(severity) {
  var sync = new SechubGithubSync({
    repository: process.env.GITHUB_REPOSITORY,
    auth: process.env.GITHUB_TOKEN,
    region: "us-east-1",
    accountNickname: accountNickname,
    severity: severity,
  });
  await sync.sync();
}

async function fetchIssues(state) {
  let issues = [];
  for await (const response of octokit.paginate.iterator(
    octokit.rest.issues.listForRepo,
    {
      ...octokitRepoParams,
      state: state,
      labels: ["security-hub", region, accountNickname],
    }
  )) {
    issues.push(...response.data);
  }
  return issues;
}

try {
  await ensureThereAreFindingsToTestAgainst();
  await runSecHubSync(["CRITICAL", "HIGH"]);
  var numIssues = (await fetchIssues("open")).length;

  // This is the simplest test... is there at least one issue created?
  if (numIssues == 0) {
    // We expect at least one CRITICAL issue to be created
    throw "FAILURE:  Check at least one issue was created.";
  } else {
    console.log("SUCCESS:  Check at least one issue was created ");
  }

  // Second test... is there now at least one issue that was closed.
  await runSecHubSync(["HIGH"]);
  var numIssuesTwo = (await fetchIssues("open")).length;
  if (numIssues - numIssuesTwo > 0) {
    console.log(
      "SUCCESS:  Check Issues are closed based on severity filtering"
    );
  } else {
    throw "FAILURE:  Check Issues are closed based on severity filtering";
  }

  // Third test... are issues reopened when appropriate?
  await runSecHubSync(["CRITICAL", "HIGH"]);
  var numIssuesThree = (await fetchIssues("open")).length;
  if (numIssues == numIssuesThree) {
    console.log("SUCCESS:  Check Issues are reopened correctly");
  } else {
    throw "FAILURE:  Check Issues are reopened correctly";
  }
} catch (error) {
  throw error;
} finally {
  console.log("Cleaning up Issues created for testing...");
  const issues = await fetchIssues("all");
  const issueNumbers = _.map(issues, "number");
  for (var i = 0; i < issueNumbers.length; i++) {
    await octokit.rest.issues.update({
      ...octokitRepoParams,
      state: "closed",
      labels: ["orphaned", "deleteme"],
      issue_number: issueNumbers[i],
    });
  }
}
