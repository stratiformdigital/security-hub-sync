<h1 align="center" style="border-bottom: none;">security-hub-sync</h1>
<h3 align="center">A utility to sync Security Hub Findings to GitHub Issues.</h3>
<p align="center">
  <a href="https://github.com/stratiformdigital/security-hub-sync/releases/latest">
    <img alt="latest release" src="https://img.shields.io/github/release/stratiformdigital/security-hub-sync.svg">
  </a>
  <a href="https://www.npmjs.com/package/@stratiformdigital/security-hub-sync">
    <img alt="npm latest version" src="https://img.shields.io/npm/v/@stratiformdigital/security-hub-sync/latest.svg">
  </a>
  <a href="https://codeclimate.com/github/stratiformdigital/security-hub-sync/maintainability">
    <img alt="Maintainability" src="https://api.codeclimate.com/v1/badges/ed37d65c137b0d54c158/maintainability">
  </a>
  <a href="https://github.com/semantic-release/semantic-release">
    <img alt="semantic-release: angular" src="https://img.shields.io/badge/semantic--release-angular-e10079?logo=semantic-release">
  </a>
  <a href="https://dependabot.com/">
    <img alt="Dependabot" src="https://badgen.net/badge/Dependabot/enabled/green?icon=dependabot">
  </a>
  <a href="https://github.com/prettier/prettier">
    <img alt="code style: prettier" src="https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square">
  </a>
</p>

## Usage

```
npm install @stratiformdigital/security-hub-sync

...

import { SechubGithubSync } from "@stratiformdigital/security-hub-sync";
...

var mySync = new SechubGithubSync({
    repository: "myorgname/myrepositoryname", // (required) The name of the repository in which to create Issues.  If GH Actions, use process.env.GITHUB_REPOSITORY
    auth: process.env.GITHUB_TOKEN, // (required)  A PAT with access to create issues.  If GH Actions, use process.env.GITHUB_TOKEN
    accountNickname: "dev", // (required) A sensible account nickname; will be used to label issues.
    region: "us-east-1", // (optional, default: us-east-1) The SecHub region at which to look.
    severity: ["CRITICAL","HIGH"], // (optional, default: ['CRITICAL','HIGH']) The finding types for which you want to create issues.
  });
  await mySync.sync();
```

## Information

This package syncs AWS Security Hub Findings to GitHub Issues.

- When the sync utility is run, each Security Hub Finding type (Title) is represented as a single issue. So if you have violated the 'S3.8' rule three individual times, you will have one S3.8 GH Issue created.
- By default, CRITICAL and HIGH severity findings get issues created in GH. However, this is configurable in either direction (more or less sensitivity).
- When the utility runs, previously created GH Issues that no longer have an active finding are closed. In this way, GH Issues can be automatically closed as the Findings are resolved, if you run the utility on a schedule (recommended).

## Assorted Notes/Considerations

Previously, this package would create one issue per finding, instead of one issue per finding type. This was recently changed, as there were too many instances of many issues created for the same problem/fix. Let us know if the new logic doesn't suit you.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

See [LICENSE](LICENSE) for full details.
