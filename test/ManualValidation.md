# Manual Validation
Our goal is to automate as much testing as possible with unit and integration tests, please see [Test.bats](https://github.com/deislabs/ratify/blob/main/test/bats/test.bats) script to review end to end scenario tested today.  While we are working on improving our coverage and sorting out cloud subscriptions account to use for testing, here is the list of scenario that currently requires manual validation.  

## Coverage Matrix
|                      | E2E available | Notes                                                                |
|----------------------|---------------|----------------------------------------------------------------------|
| Azure auth provider |  No           |                                                                      |
| K8 secrets auth provider           |               |                                                                      |
| Docker config auth provider  |               |                                                                      |
| AWS Auth Provider    |    No         |                                                                      |
| Cosign Verifier      |    Yes        | Known issue [231](https://github.com/deislabs/ratify/issues/231), validation should cover both Azure and AWS as they are differences in code path |
| Notary Verifier      |               | Yes           |                                                                      