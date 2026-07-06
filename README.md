# Secure Asset Transfer Protocol (SATP) Core

This is the working area for the IETF [SATP Working Group](https://datatracker.ietf.org/wg/satp/documents/) Internet-Draft, "Secure Asset Transfer Protocol (SATP) Core".

* [Editor's Copy](https://ietf-satp.github.io/draft-ietf-satp-core/#go.draft-ietf-satp-core.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-satp-core)
* [Working Group Draft](https://datatracker.ietf.org/doc/html/draft-ietf-satp-core)
* [Compare Editor's Copy to Working Group Draft](https://ietf-satp.github.io/draft-ietf-satp-core/#go.draft-ietf-satp-core.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/ietf-satp/draft-ietf-satp-core/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

The Makefile provides several [useful targets](https://github.com/martinthomson/i-d-template/blob/main/main.mk#L1):
- `make fix-lint` - Runs editorconfig-checker to validate formatting and style
- `make` - Builds formatted text and HTML versions of the draft

These tools help maintain consistent formatting and catch common issues before submission.

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

### Python version requirement

The build toolchain requires **Python 3.10 or later**. If `make` fails with
`Warning: python needs to be at least 3.10`, install a newer version and
activate it before building:

```sh
pyenv install 3.12.13   # only needed once
pyenv local 3.12.13     # pins the version for this directory
make
```

The `pyenv local` command writes a `.python-version` file that is already
listed in `.gitignore`, so it will not be committed.

