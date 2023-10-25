# Contributing

This repository relates to activities in the Internet Engineering Task Force
([IETF](https://www.ietf.org/)). All material in this repository is considered
Contributions to the IETF Standards Process, as defined in the intellectual
property policies of IETF currently designated as
[BCP 78](https://www.rfc-editor.org/info/bcp78),
[BCP 79](https://www.rfc-editor.org/info/bcp79) and the
[IETF Trust Legal Provisions (TLP) Relating to IETF Documents](http://trustee.ietf.org/trust-legal-provisions.html).

Any edit, commit, pull request, issue, comment or other change made to this
repository constitutes Contributions to the IETF Standards Process
(https://www.ietf.org/).

You agree to comply with all applicable IETF policies and procedures, including,
BCP 78, 79, the TLP, and the TLP rules regarding code components (e.g. being
subject to a Simplified BSD License) in Contributions.
## Working Group Information

Discussion of this work occurs on the [Secure Asset Transfer Protocol
Working Group mailing list](mailto:sat@ietf.org)
([archive](https://mailarchive.ietf.org/arch/browse/sat/),
[subscribe](https://www.ietf.org/mailman/listinfo/sat)).
In addition to contributions in GitHub, you are encouraged to participate in
discussions there.

**Note**: Some working groups adopt a policy whereby substantive discussion of
technical issues needs to occur on the mailing list.

You might also like to familiarize yourself with other
[Working Group documents](https://datatracker.ietf.org/wg/satp/documents/).

## Process
The collaboration process follows standard engineering and open-source practices. To contribute to this draft, create a fork of the repo, do your changes, and open a pull request. A discussion will happen on the PR thread. Upon approval (contingent to the decision of the WP), the PR is merged and your changes are incorporated on the main draft. Detailed instructions:

1. Please [fork the repository](https://docs.github.com/en/get-started/quickstart/fork-a-repo).

2. Add 'upstream' repo to list of remotes
`git remote add upstream https://github.com/ietf-satp/draft-ietf-satp-core`.

3. Verify the new remote named 'upstream'
`git remote -v`. You should now have an `origin` remote (your fork), and the `upstream`.

4. (optional) Run these commands whenever you want to synchronize with the main branch:

        git fetch upstream
        git checkout main
        git rebase upstream/main

5.  Create and checkout your branch.
        `git checkout -b BRANCH_NAME`

6. Do your changes to the draft. The draft is in [IETF Markdown format](https://authors.ietf.org/en/drafting-in-markdown).

7. Commit changes to your branch.
# Commit and push your changes to your fork

    git add -A
    git commit -s -m "docs(DRAFT_NAME): DESCRIPTION"
    git push origin BRANCH_NAME

8. [Create a Pull Request on Github](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request).

9. Discussion takes place.
