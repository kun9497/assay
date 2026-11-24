# assay

> **컨테이너·바이너리·파일시스템을 위한 취약점 스캐너 — KISA/KNVD 한국어 권고 데이터를 1급 소스로.**

*[English](README.md) · 한국어*

[![CI](https://github.com/kun9497/assay/actions/workflows/ci.yml/badge.svg)](https://github.com/kun9497/assay/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/kun9497/assay?sort=semver)](https://github.com/kun9497/assay/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/kun9497/assay.svg)](https://pkg.go.dev/github.com/kun9497/assay)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

`assay`는 이미지·바이너리·디렉터리·SBOM에서 패키지 인벤토리를 만들고, 스스로 관리하는
취약점 데이터베이스와 대조해, CI가 게이트로 삼을 수 있는 판정을 돌려줍니다. anchore
생태계가 세 도구(`syft` + `vunnel`/`grype-db` + `grype`)로 나눠 하는 일 — 인벤토리,
데이터베이스, 매칭 — 을 한 도구로 처리합니다. KISA/KNVD 한국어 권고 데이터가 grype를 다시
쓰지 않고 이 프로젝트가 존재하는 이유입니다.

<p align="center">
  <img src="docs/assets/demo.svg" alt="assay scan alpine:3.19 — 실제 출력" width="820">
</p>

## 설치

```bash
# 사전 빌드 바이너리 (Linux/macOS, amd64/arm64) — PATH 위로 바로 설치; Windows는 아래
sh -c 't=$(mktemp) && (curl -sSfL --connect-timeout 5 --proto-redir =https -o "$t" https://raw.githubusercontent.com/kun9497/assay/f864a8b272bf0f6f1f2a7fca9f39ea341f22d68f/install.sh || curl -sSfL --connect-timeout 5 --proto-redir =https -H "Accept:application/vnd.github.raw+json" -o "$t" "https://api.github.com/repos/kun9497/assay/contents/install.sh?ref=f864a8b272bf0f6f1f2a7fca9f39ea341f22d68f") && sudo sh "$t" -b /usr/local/bin; s=$?; rm -f "$t"; exit $s'
```

스크립트는 프로젝트 서명 키를 내장하고 릴리스 체크섬 파일의 서명을 `openssl`(또는 `cosign`)로
먼저 검증한 뒤 체크섬을 확인하고 OS/arch에 맞는 에셋을 고릅니다. URL에는 설치 스크립트의 Git 커밋을 고정합니다. raw 호스트에 연결하지 못하면 같은 커밋의 같은 파일을 GitHub contents API에서 받습니다.
스크립트는 임시 파일(`mktemp`)로 받아 다운로드가 성공했을 때만 실행하고, 설치가 성공하든 실패하든 그 파일을 지우며(중단된 실행은 `$TMPDIR`에 본인만 읽을 수 있는 파일을 남길 수 있습니다),
줄의 종료 상태는 설치의 것입니다(`curl`을 `sh`로 파이프하면 다운로드가 실패해도 0을 반환했고, 작업 디렉터리의 고정
파일명은 같은 이름의 파일을 덮어썼습니다). 현재 디렉터리의 파일은 건드리지 않습니다. `-b` 없이 실행하면 `./bin`에
설치됩니다(sudo 불필요 — PATH 등록은 직접). 다른 릴리스는 같은 줄 안에서 `-b /usr/local/bin` 뒤에 태그를 붙여
(`… -b /usr/local/bin vX.Y.Z; s=$?; …`) 설치하며, 같은 키로 검증합니다. 체크섬 파일에 서명이 없는 릴리스는 체크섬만으로 설치하지 않고
거부합니다: v0.10.0 이 첫 서명 릴리스이므로 그보다 오래된 것은 `go install` 이나 릴리스 페이지로
설치하세요.

v0.18.3 이전 설치 스크립트를 root로 실행했다면 실행 파일의 소유자를 확인하고, root가 아니면
위 명령을 다시 실행하세요. 이전 설치기는 아카이브의 빌드 러너 UID를 복원할 수 있었으며,
v0.18.0 릴리스 자산에서 이를 확인했습니다. 현재 설치기는 실행 파일을 설치 사용자 소유로 만듭니다.

sudo가 없는 러너에서는 설치 명령의 `sudo sh "$t" -b /usr/local/bin`을
`sh "$t" -b "$HOME/.local/bin"`으로 바꾸고, 스캔 스텝에서 `export PATH="$HOME/.local/bin:$PATH"`를 실행하세요.

Windows에서는 PowerShell 5.1 또는 7에서 다음 명령을 실행합니다. v0.18.5는 Windows 바이너리를 제공하지 않았고, v0.18.6부터 다시 제공합니다.

```powershell
& { $ErrorActionPreference = "Stop"; try { $s = irm -TimeoutSec 8 https://raw.githubusercontent.com/kun9497/assay/f864a8b272bf0f6f1f2a7fca9f39ea341f22d68f/install.ps1 } catch { $s = irm -TimeoutSec 8 -Headers @{Accept="application/vnd.github.raw+json"} "https://api.github.com/repos/kun9497/assay/contents/install.ps1?ref=f864a8b272bf0f6f1f2a7fca9f39ea341f22d68f" }; & ([scriptblock]::Create($s)) }
```

`install.ps1`은 .NET으로 서명을 검증하고 `%LOCALAPPDATA%\Programs\assay`에 설치합니다.
`$env:ASSAY_INSTALL_DIR`로 디렉터리를, `$env:ASSAY_VERSION`으로 릴리스를 지정할 수 있습니다.
빠른 시작을 실행하기 전에 현재 PowerShell 세션의 PATH에 설치 디렉터리를 추가하세요.
설치 경로를 바꿨다면 아래 기본 경로 대신 그 디렉터리를 넣으세요.

```powershell
$env:Path = (Join-Path $env:LOCALAPPDATA 'Programs\assay') + ';' + $env:Path
```

**GitHub 다운로드 시간이 초과되면** Git·Python 3·curl을 사용해 아래 명령을 실행하세요. `assay-install`이 아직 없는 디렉터리에서 시작하고, 각 명령이 성공한 뒤 다음 명령을 실행합니다. Git 경로로 고정한 설치 스크립트를 가져오므로 raw 호스트와 공개 API에 연결할 수 없을 때도 사용할 수 있습니다.

```text
git clone --no-checkout https://github.com/kun9497/assay.git assay-install
git -C assay-install checkout --detach f864a8b272bf0f6f1f2a7fca9f39ea341f22d68f
```

Linux·macOS에서는 `python3 assay-install/scripts/recover-install.py -b "$HOME/.local/bin"`, Windows에서는 `py -3 assay-install/scripts/recover-install.py`를 실행합니다(Python 3 명령이 `python`이면 그 이름을 사용하세요). Windows 복구는 현재 PowerShell 실행 정책에 따라 체크아웃한 스크립트를 실행합니다. 연결 실패 시 도구가 DNS에서 받은 다른 주소로 공식 HTTPS 자산 호스트에 재시도합니다. 설치 스크립트가 서명과 체크섬을 확인한 뒤 바이너리를 교체합니다. 프록시가 GitHub의 모든 자산 주소를 차단하면 해당 주소에 대한 접근이 필요합니다. 비인증 GitHub contents API에는 [IP별 호출 제한](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)이 있습니다.

<details>
<summary>다른 설치 방법</summary>

```bash
# Go 로
go install github.com/kun9497/assay/cmd/assay@latest

# 소스에서
git clone https://github.com/kun9497/assay.git && cd assay && make build   # -> bin/assay
```

소스에서 설치할 때는 CVE-2026-97054가 수정된 Go를 사용하세요.
1.26 계열은 1.26.11부터, 1.27 계열은 1.27.4부터 수정됐습니다.
설치한 실행 파일의 빌드 버전은 `go version -m <assay 실행 파일 경로>`로 확인할 수 있습니다.
[Go 취약점 공지](https://pkg.go.dev/vuln/GO-2026-6859)

[릴리스 페이지](https://github.com/kun9497/assay/releases)에서 버전별로 배포한 바이너리와 서명된 체크섬을 확인할 수 있습니다.
</details>

## 빠른 시작

위 설치 명령을 CI 러너에서 실행한 뒤, 아래 블록을 셸 스텝 하나로 실행하세요.
GHCR에서 서명된 DB를 받고 공개 Alpine 이미지를 스캔합니다. Docker 데몬이나 로그인은 필요 없습니다.
러너에는 로컬 DB를 저장할 공간이 필요합니다. 2026년 11월 Windows에서 측정한 **논리 파일 길이는
6 GiB**였습니다. [측정 방법과 메모리 모델](docs/operating-envelope.ko.md#3-메모리-모델)을 참고하세요.
크기는 아티팩트와 플랫폼에 따라 달라집니다. 기존 DB를 갱신하는 동안에는 이전 DB와 새 DB를
함께 보관할 여유 공간을 확보하세요.
실제 빌드에서는 `IMAGE`를 방금 레지스트리에 푸시한 이미지의 다이제스트 참조로, `--platform`을 배포할 플랫폼으로 바꾸세요.

```sh
set -e
assay version
assay db update
assay db status --output json > assay-db.json

IMAGE='mirror.gcr.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1'
assay scan "$IMAGE" --platform linux/amd64 --config none \
  --fail-on high --fail-on-incomplete --output json > assay-report.json
```

`db update`는 DB를 설치하기 전에 서명을 검증합니다. `assay-db.json`의 `artifact.signature` 값은
`verified`여야 합니다. `artifact.digest`와 `artifact.signedBy`에서 DB와 서명 키를 확인할 수 있습니다.
`--config none`은 체크아웃의 `.assay.yaml`이 탐지 결과를 면제하는 일을 방지합니다.

| 스캔 종료 코드 | 위 옵션을 적용한 CI 판정 |
|---|---|
| `0` | **통과.** 면제되지 않은 High·Critical 탐지와 불완전 평가가 없습니다. 더 낮은 등급의 취약점은 있을 수 있습니다. |
| `1` | **실패.** 면제되지 않은 High·Critical 탐지가 있습니다. 보고서의 `findings`를 확인하세요. |
| `2` | **실패.** 스캔을 끝낼 수 없었거나 평가가 불완전합니다. stderr와, 보고서가 있으면 `summary`와 `skipped`를 확인하세요. `1`보다 우선합니다. |

스캔을 스텝의 마지막 명령으로 두세요. JSON을 읽거나 업로드하는 일은 실패 시에도 실행되는 별도 스텝에 두면 됩니다.
`jq`에 파이프로 연결하면 스캔 종료 코드가 가려질 수 있고, 초기에 실패하면 보고서 파일이 비어 있을 수 있습니다.
`inventoryScope`에서 이미지 스캔 범위를 확인하세요. `summary.components`가 0이면 인벤토리에서 읽은 패키지가 없다는 뜻입니다.
심각도 기준 없이 결과를 보려면 `assay scan "$IMAGE" --platform linux/amd64`를 실행하세요.
이미지를 고정해도 DB가 갱신되면 탐지 결과가 달라질 수 있습니다.

<details>
<summary>PowerShell CI 스텝에서 실행하기</summary>

앞선 스텝에서 설치했다면 위 설치 절의 PATH 추가 명령을 이 스텝에서도 실행하세요.

```powershell
$ErrorActionPreference = 'Stop'
assay db update
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
assay db status
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$image = 'mirror.gcr.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1'
assay scan $image --platform linux/amd64 --config none --fail-on high --fail-on-incomplete
exit $LASTEXITCODE
```

</details>

[GitHub Actions 워크플로](docs/ci/github-actions.yml)를 `.github/workflows/`에 복사하면 Security 탭에 SARIF 경보를 게시합니다.
GitHub.com 공개 저장소에서 이 기능을 사용할 수 있습니다. 조직 소유 비공개 또는 내부 저장소에서는 저장소 설정에서 GitHub Code Security를 활성화하세요.
[GitHub의 SARIF 업로드 요건](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

GitLab에서는 [GitLab CI 잡](docs/ci/gitlab-ci.yml)을 `.gitlab-ci.yml`에 추가하면 보고서를 잡 아티팩트로 보관합니다. 두 예제 모두 설치 단계가 포함돼 있습니다.
푸시 전에 로컬 Docker 빌드를 검사하려면 `docker save -o image.tar my-app:ci`로 저장하고
위 스캔의 입력을 `docker-archive:image.tar`로 바꾸세요. CycloneDX·SPDX SBOM은 `assay scan sbom.cdx.json`,
Go 바이너리나 lockfile이 있는 디렉터리는 `assay scan ./my-service`로 스캔할 수 있습니다.
`--output sarif`는 코드 스캔용 보고서를 쓰고, `--explain`은 개별 탐지의 근거를 보여줍니다.

**프라이빗 레지스트리.** 레지스트리 이미지를 스캔할 때 자격증명은 다음 순서로 시도합니다.
`ASSAY_REGISTRY_AUTH_USERNAME` + `ASSAY_REGISTRY_AUTH_PASSWORD`(또는
`ASSAY_REGISTRY_AUTH_TOKEN`), 그다음 `docker login`(`DOCKER_CONFIG` 또는
`~/.docker/config.json`, 자격증명 헬퍼 포함), 그다음 podman의 것(`REGISTRY_AUTH_FILE` 또는
`$XDG_RUNTIME_DIR/containers/auth.json`)입니다. 환경 변수 자격증명은
`ASSAY_REGISTRY_AUTH_AUTHORITY`로 다른 레지스트리를 지정하지 않는 한 타깃 자신의 레지스트리에만
제시되고, 반쪽만 설정되면 exit 2이며, 값은 출력되지 않습니다. `--platform os/arch[/variant]`로
플랫폼을 고릅니다. 기본값은 Linux와 Assay 실행 파일의 아키텍처를 조합한 값입니다(예: Windows x64에서도
`linux/amd64`). 스캔한 플랫폼과 다이제스트는 stderr와 JSON `image` 객체에서 확인할 수 있습니다.

**판정을 만든 것.** 모든 JSON·SARIF 리포트에는 `provenance` 객체가 들어갑니다. assay 빌드, 데이터베이스
(그리고 `db update`가 받아 온 배포 아티팩트의 digest), 대상 내용의 해시, 모든 게이트 플래그, 각 ignore
규칙과 VEX 문서의 해시와 일치한 finding 수를 담으며, 타임스탬프가 없어 같은 입력은 여전히 같은
바이트를 냅니다. `--provenance <path>`는 실행 시작·종료 시각, exit code, 리포트의 sha256을 담은 별도
파일도 씁니다. 리포트가 나오기 전에 exit 2로 끝난 스캔에서도 씁니다.

## 무엇을 커버하나

- **grype가 provider를 제공하는 모든 OS 계열** — Alpine, Debian, Ubuntu, RHEL, Rocky,
  AlmaLinux, Amazon Linux 2/2023, Oracle Linux, Fedora, SLES/openSUSE Leap, Wolfi,
  Chainguard, MinimOS, Echo, Azure Linux/CBL-Mariner, Alpaquita, Photon, Arch, Red Hat
  Hummingbird, CleanStart — 여기에 Bitnami 애플리케이션 레이어까지, 세 가지 rpmdb
  백엔드(BerkeleyDB, SQLite, ndb)에 걸쳐.
- **8개 언어 생태계** — Go, npm, PyPI, crates.io, Maven, RubyGems, NuGet, Packagist —
  바이너리·디렉터리·열세 가지 lockfile 형식에서. pnpm과 yarn berry도 포함됩니다. 컨테이너
  이미지 안에서는 두 고정 위치(D160): 전역 `node_modules` 루트 아래에 설치된 npm 패키지와 표준 bin
  디렉터리의 Go 바이너리. Python, Java, 그리고 이미지의 다른 어디에 있든 나머지는 읽지
  않습니다(D70, [미룸](docs/deferred-decisions.md)). 모든 이미지 스캔은 무엇을 읽고 읽지 않았는지를
  stderr, SARIF, JSON 의 `inventoryScope` 에 정확히 밝힙니다(D141).
- **업스트림이 게시를 멈춘 릴리스는 표시된 채 남습니다** — 업스트림이 더 이상 서비스하지 않는 키는
  동결됩니다(D110): 마지막 권고가 유지되고, 그 키의 모든 finding에 `frozenSince`가 붙으며, 그 뒤
  업스트림이 낸 수정은 빠져 있을 수 있습니다 — 표, SARIF, `--explain`이 날짜 옆에 그렇게 말하고
  JSON은 날짜를 `frozenSince`로 싣습니다. Debian 11이 오늘 동결 상태이고(bullseye LTS는
  2026-08-31 종료; Freexian ELTS 수정은 읽지 않음), 업스트림이 내린 다른 모든 키도 그렇습니다.
  서비스를 위한 운영 지침은
  [docs/integrations.ko.md](docs/integrations.ko.md#직접-만들지-않은-타깃에-assay-운영하기)에.
- **모든 소스의 등급을 보존** — 두 데이터베이스가 한 CVE를 두고 흔히 엇갈립니다. finding은
  각 소스의 밴드·점수·수정 버전을 모두 담고 게이트는 그 최고치를 취하므로, 리포트가 자기
  판정과 어긋나지 않습니다.
- **일곱 개 게이트** — `--fail-on <band>`, `--fail-on-unknown`, `--fail-on-incomplete`,
  `--fail-on-unfixable`(`=wont-fix` 포함), `--fail-on-kev`, `--fail-on-epss`,
  `--fail-on-eol`. 평가할 수 없는 패키지는 개수와 함께 skipped로 보고되며, 조용히 clean
  판정에 섞이는 일이 없습니다.
- **아티팩트가 실어 나르는 보강 데이터** — NVD 등급, EPSS 점수, CISA KEV 등재, EOL 상태.
  KISA의 한국어 산문은 `assay db build`로 로컬에서 얻습니다.
- **보이는 채로 남는 면제** — 수용하기로 한 finding은 `.assay.yaml` ignore 파일로
  억제합니다(사유는 필수, 만료일은 선택), 그리고 `--vex`는 생산자의 OpenVEX 문서를
  같은 방식으로 적용합니다. 이미지의 OS 패키지에도 적용되며, 이미지를 명시한 statement는 그
  이미지에만 적용됩니다. 억제된 finding은 게이트를 건드리지 않지만 모든 출력
  형식에서 개수와 함께 표시되며, 각각 자신의 waiver가 어디서 왔는지 라벨이 붙고,
  GitHub code scanning에는 사라진 것이 아니라 dismissed로 보입니다. 사용법은
  [docs/integrations.ko.md](docs/integrations.ko.md#받아들인-finding-waive하기)에.

## 어떻게 맞물리나

```
  이미지 / 바이너리 / dir / SBOM  ──▶  패키지 인벤토리  ──▶  취약점 매칭  ──▶  판정
```

데이터베이스는 스캔과 직교합니다: `assay db update`가 쓰고, 스캔은 읽기만 하며, SBOM이나
로컬 tarball 스캔은 네트워크 호출을 전혀 하지 않습니다. 종료 코드는 계약입니다 — `0` 어떤 게이트도
걸리지 않음, `1` `--fail-on` 이상의 finding, `2` 실행 불가 또는 신뢰 불가 — 우선순위는
`2` > `1` > `0`. `0`은 "취약점 없음"이 아닙니다: `--fail-on*` 플래그 없이 실행한 스캔은 finding을
나열하고도 0으로 끝나고, finding이 모두 waive된 스캔이나 컴포넌트가 없는 SBOM도 0입니다. 종료
코드만이 아니라 보고서의 summary를 읽으세요.

## 문서

- **[docs/DESIGN.md](docs/DESIGN.md)** — 전체 설계, 출시된 모든 기능을 담은 로드맵,
  아키텍처, 데이터베이스 부트스트랩 가이드. 거기의 로드맵 체크박스가 무엇이 만들어졌는지의
  기준 기록입니다. ([한국어](docs/DESIGN.ko.md))
- **[docs/deferred-decisions.md](docs/deferred-decisions.md)** — 의도적으로 *만들지 않은*
  것과 그 이유, 각각 재방문 트리거와 함께. ([한국어](docs/deferred-decisions.ko.md))
- **[docs/integrations.md](docs/integrations.md)** — CI 통합: 복사해 쓰는 GitHub Actions·
  GitLab CI 예제, SARIF 업로드, 종료 코드 게이팅. ([한국어](docs/integrations.ko.md))
- **[docs/comparison.md](docs/comparison.md)** — grype(주간 실측)·trivy(스펙 수준)와의
  비교, 그리고 각 도구의 정책이 의도적으로 갈리는 지점. ([한국어](docs/comparison.ko.md))
- **[docs/superpowers/specs/2026-07-29-assay-roadmap.md](docs/superpowers/specs/2026-07-29-assay-roadmap.md)**
  — 레퍼런스 설계, 모든 결정을 번호가 붙은 `D` 항목으로 근거와 함께 기록.
- **[docs/compatibility.md](docs/compatibility.md)** — JSON, SARIF, 데이터베이스 출력을 쓰는
  쪽이 릴리스를 넘어 기댈 수 있는 것과 `schemaVersion` 증가가 뜻하는 것.
  ([한국어](docs/compatibility.ko.md))
- **[CHANGELOG.md](CHANGELOG.md)** — 릴리스마다 바뀐 것. ([한국어](CHANGELOG.ko.md))

모든 문서는 `X.md` / `X.ko.md` 짝으로 배포되며, 영어가 정본입니다.

## 기여

`make build`(CGO_ENABLED=0), `make test`(`-race`, C 툴체인 필요 — 없으면
`go test ./...`로 대체), `make lint`, `make fmt`. CI는 Go 1.26에서 gofmt-check → vet →
test-race → build를 돕니다. 변경에 필요한 것은 [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md)에
있습니다. 보안 문제는 [SECURITY.ko.md](SECURITY.ko.md)에 적힌 대로 비공개로 알려 주십시오.

## 고지

`assay`는 주어진 데이터에서 알려진 취약점을 보고할 뿐, 보안을 보장하지 않으며, 깨끗한
스캔이 안전의 증명은 아닙니다. 중요한 것은 상류 권고에 대조해 확인하세요.

## 라이선스

[Apache License 2.0](LICENSE).
