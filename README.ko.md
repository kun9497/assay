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
# 사전 빌드 바이너리 (Linux/macOS, amd64/arm64) — PATH 위로 바로 설치
curl -sSfL https://raw.githubusercontent.com/kun9497/assay/6a8889050ebf24615b1ebd277ebbbda508babfbd/install.sh | sudo sh -s -- -b /usr/local/bin
```

스크립트는 프로젝트 서명 키를 내장하고 릴리스 체크섬 파일의 서명을 `openssl`(또는 `cosign`)로
먼저 검증한 뒤 체크섬을 확인하고 OS/arch에 맞는 에셋을 고릅니다. 위 줄은 최신 릴리스가 빌드된
커밋을 가리킵니다 — 옮겨질 수 있는 브랜치나 태그가 아니라 — 그리고 릴리스 잡이 이 줄을 갱신합니다.
`-b` 없이 실행하면 `./bin`에 설치되며(sudo 불필요 — PATH 등록은 직접), `-s -- vX.Y.Z`는 같은 키로
검증해 다른 릴리스를 설치합니다. 체크섬 파일에 서명이 없는 릴리스는 체크섬만으로 설치하지 않고
거부합니다: v0.10.0 이 첫 서명 릴리스이므로 그보다 오래된 것은 `go install` 이나 릴리스 페이지로
설치하세요.

<details>
<summary>다른 설치 방법</summary>

```bash
# Go 로
go install github.com/kun9497/assay/cmd/assay@latest

# 소스에서
git clone https://github.com/kun9497/assay.git && cd assay && make build   # -> bin/assay
```

모든 플랫폼용 사전 빌드 바이너리와 체크섬은 각
[릴리스](https://github.com/kun9497/assay/releases/latest)에 첨부됩니다.
</details>

## 빠른 시작

```bash
# 1. 취약점 데이터베이스 받기 (수 초 — 발행된 OCI 아티팩트를 당겨오고
#    assay 에 내장된 키로 서명을 검증)
assay db update

# 2. 스캔
assay scan alpine:3.19                    # 레지스트리 이미지
assay scan --platform linux/arm64 alpine:3.19   # 멀티 플랫폼 이미지의 다른 플랫폼
ASSAY_REGISTRY_AUTH_TOKEN=$TOKEN assay scan registry.example.com/team/app:1.0   # 프라이빗 레지스트리
assay scan docker-archive:image.tar       # 로컬 tarball — 네트워크 없음
assay scan sbom.cdx.json                  # CycloneDX 또는 SPDX SBOM
assay scan ./my-service                   # Go 바이너리, 또는 lockfile이 있는 디렉터리

# 3. CI 게이트 — 임계 이상이면 exit 1, 신뢰할 수 없으면 exit 2
assay scan alpine:3.19 --fail-on high
```

`assay scan`은 결과를 stdout, 진단을 stderr로 보내므로
`assay scan … --output json | jq`가 깨끗하게 유지됩니다. `--output`은 `sarif`(GitHub 코드
스캐닝용)와 `table`(기본값)도 지원하고, `--explain`은 한 finding의 전체 근거를 보여줍니다.

**프라이빗 레지스트리.** 레지스트리 이미지를 스캔할 때 자격증명은 다음 순서로 시도합니다.
`ASSAY_REGISTRY_AUTH_USERNAME` + `ASSAY_REGISTRY_AUTH_PASSWORD`(또는
`ASSAY_REGISTRY_AUTH_TOKEN`), 그다음 `docker login`(`DOCKER_CONFIG` 또는
`~/.docker/config.json`, 자격증명 헬퍼 포함), 그다음 podman의 것(`REGISTRY_AUTH_FILE` 또는
`$XDG_RUNTIME_DIR/containers/auth.json`)입니다. 환경 변수 자격증명은
`ASSAY_REGISTRY_AUTH_AUTHORITY`로 다른 레지스트리를 지정하지 않는 한 타깃 자신의 레지스트리에만
제시되고, 반쪽만 설정되면 exit 2이며, 값은 출력되지 않습니다. `--platform os/arch[/variant]`로
플랫폼을 고르며, 기본값은 컨테이너 런타임이 고르는 방식 그대로 이 호스트의 플랫폼입니다. 스캔한
플랫폼과 digest는 stderr에 출력되고 JSON `image` 객체에 기록됩니다.

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
  바이너리·디렉터리·열 가지 lockfile 형식에서. pnpm과 yarn berry도 포함됩니다. 컨테이너
  이미지 내부에서는 읽지 않습니다: 이미지 스캔은 위의 OS 패키지와 Bitnami 레이어만
  인벤토리화할 뿐, 그 안에 설치된 언어 패키지는 대상에 넣지 않습니다(D70,
  [미룸](docs/deferred-decisions.md)). 모든 이미지 스캔은 이를 stderr 와 SARIF 에 밝힙니다(D141).
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
로컬 tarball 스캔은 네트워크 호출을 전혀 하지 않습니다. 종료 코드는 계약입니다 — `0` 깨끗함,
`1` `--fail-on` 이상의 finding, `2` 실행 불가 또는 신뢰 불가 — 우선순위는 `2` > `1` > `0`.

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
  — 레퍼런스 설계, 모든 결정을 `D1`…`D107`로 근거와 함께 기록.

모든 문서는 `X.md` / `X.ko.md` 짝으로 배포되며, 영어가 정본입니다.

## 기여

`make build`(CGO_ENABLED=0), `make test`(`-race`, C 툴체인 필요 — 없으면
`go test ./...`로 대체), `make lint`, `make fmt`. CI는 Go 1.26에서 gofmt-check → vet →
test-race → build를 돕니다. 변경이 지켜야 할 아키텍처 제약은
[docs/DESIGN.md](docs/DESIGN.md)를 보세요.

## 고지

`assay`는 주어진 데이터에서 알려진 취약점을 보고할 뿐, 보안을 보장하지 않으며, 깨끗한
스캔이 안전의 증명은 아닙니다. 중요한 것은 상류 권고에 대조해 확인하세요.

## 라이선스

[Apache License 2.0](LICENSE).
