# Fixtures for `keepshipping import github-actions`

The four workflow files in this directory are copied verbatim from
[`actions/starter-workflows`](https://github.com/actions/starter-workflows) at
commit `e3c451d60f119b71caebf13c98ac45da6e15b4b7`:

| File here | Source |
| --- | --- |
| `docker-publish.yml` | [`ci/docker-publish.yml`](https://raw.githubusercontent.com/actions/starter-workflows/e3c451d60f119b71caebf13c98ac45da6e15b4b7/ci/docker-publish.yml) |
| `terraform.yml` | [`deployments/terraform.yml`](https://raw.githubusercontent.com/actions/starter-workflows/e3c451d60f119b71caebf13c98ac45da6e15b4b7/deployments/terraform.yml) |
| `azure-kubernetes-service-helm.yml` | [`deployments/azure-kubernetes-service-helm.yml`](https://raw.githubusercontent.com/actions/starter-workflows/e3c451d60f119b71caebf13c98ac45da6e15b4b7/deployments/azure-kubernetes-service-helm.yml) |
| `node.js.yml` | [`ci/node.js.yml`](https://raw.githubusercontent.com/actions/starter-workflows/e3c451d60f119b71caebf13c98ac45da6e15b4b7/ci/node.js.yml) |

They are the workflows GitHub offers a new repository, unmodified — including
the `$default-branch` placeholders and the placeholder values in `env:`. Nothing
here is edited to suit the importer, because the point of these files is to be
the ones people actually have.

The upstream licence follows, as it does for every file above.


Copyright (c) 2020 GitHub

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. THIS LICENSE DOES NOT GRANT YOU RIGHTS TO USE ANY CONTRIBUTORS'
NAME, LOGO, OR TRADEMARKS.
