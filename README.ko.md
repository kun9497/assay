# assay

> **컨테이너·바이너리·파일시스템을 위한 취약점 스캐너.**

*[English](README.md) · 한국어*

`assay`는 컨테이너 이미지, 바이너리, 디렉터리에서 SBOM을 생성하거나 — 이미 갖고 있는 SBOM을
받아서 — 거기에 영향을 주는 알려진 취약점을 보고합니다.

```
  이미지 / 바이너리 / 디렉터리 / SBOM  ──▶  패키지 인벤토리  ──▶  취약점 매칭  ──▶  판정
```

---

## 현재 상태

🚧 **초기 개발 단계. Alpine 컨테이너는 끝에서 끝까지 스캔되고, 다른 배포판은 아직입니다.**

`assay db update`가 OSV로부터 로컬 데이터베이스를 만들고, `assay scan`이 거기에 매칭합니다 —
Go, npm, PyPI, 그리고 **Alpine**. **컨테이너 이미지를 직접 읽으므로 syft가 더 이상 필요하지
않습니다.** 실제 대상에서 grype와 동일한 finding을 보고합니다: 개수만 같은 것이 아니라 CVE
집합이 같습니다. [로드맵](#로드맵) 참조.

Alpine 패키지는 **소스 패키지를 거쳐** 매칭됩니다. `openssl` 권고가 설치된 `libssl3`에
도달하고, 리포트가 둘 다 표시합니다. distro 스캐너가 조용히 놓치는 지점이 바로 이 간접 참조입니다.

Go **바이너리**와 **디렉터리**도 읽습니다. 앞은 `debug/buildinfo`로, 뒤는 `go.mod`로 읽으며,
Go 툴체인 자체는 `stdlib` 패키지로 매칭합니다.

finding은 저장된 CVSS 벡터에서 뽑은 심각도 밴드를 갖고, `--fail-on`, `--fail-on-unknown`,
`--fail-on-incomplete`가 그것을 CI가 게이팅할 수 있는 종료 코드로 바꿉니다. `--output json`은
안정된 기계 판독 문서를, `--explain <id>`는 특정 finding이 왜 매칭됐는지를 출력합니다.

finding은 처음 매칭된 하나가 아니라 **모든** 데이터베이스의 평가를 유지하고, 판정은 그중 가장
높은 밴드입니다. 실제 Django 3.2.12 스캔에서는 finding 19건 중 15건을 두 출처가 함께 기술하고,
그중 14건은 둘 중 하나만 평가를 매깁니다. 이 변경 전에는 판정 14건이 패키지 인덱스가 어느
레코드를 먼저 나열했는지에 달려 있었다는 뜻입니다.

그 아래 내용은 여전히 구현이 아니라 설계 목표입니다. Alpine이 아닌 이미지는 **읽기는 하지만
매칭할 수 없습니다** — `assay scan debian:12`는 지원하는 패키지 데이터베이스를 찾지 못했다고
말하고 2를 반환합니다. 검사한 적 없는 이미지를 깨끗하다고 보고하지 않습니다.

[`docs/superpowers/specs/2026-07-29-assay-roadmap.ko.md`](docs/superpowers/specs/2026-07-29-assay-roadmap.ko.md)에
전체 설계와 각 결정의 근거가 담겨 있습니다.

## 범위

`assay`는 전체 경로를 한 도구에서 다룹니다 — 패키지 인벤토리 생성, 취약점 데이터베이스 구축,
그리고 둘의 매칭. anchore 생태계에서는 이것이 `syft`, `vunnel` + `grype-db`, `grype`라는 세
개의 별도 프로젝트입니다.

기존 스캐너들은 훌륭하고 충분히 검증되어 있습니다. 프로덕션에서는 그것들을 쓰십시오. 이 도구를
규정하는 것은 두 가지입니다:

- **국내 취약점 데이터.** KISA/KNVD는 NVD와 OSV가 늦게 다루거나 아예 다루지 않는 소프트웨어에
  대한 권고와 KVE 식별자를 발행합니다. 주요 스캐너들은 이를 수집하지 않습니다.
- **설명 가능한 매칭.** 모든 finding이 그것을 만들어낸 근거를 함께 전달합니다 — 어떤 범위,
  어떤 comparer, 어떤 비교 결과였는지. 판정만 던지지 않습니다.

설계 목표, 우선순위 순:

1. **설명 가능할 것** — 모든 finding이 매칭되었다는 사실이 아니라 *왜* 매칭되었는지를 말합니다.
2. **오프라인 동작** — 스캔은 취약점 데이터를 절대 받아오지 않고, 이미 디스크에 있는 것을
   스캔할 때는 네트워크 호출이 아예 없습니다. 원격 **대상**만, 그것도 사용자가 원격을 지목했을
   때만 받아옵니다. `assay scan alpine:3.19`는 외부로 나가고
   `assay scan docker-archive:alpine.tar`는 나가지 않습니다.
3. **지루한 출력** — 결정적이고, diff 가능하고, CI 친화적으로.

설정 오류 스캔, 시크릿 스캔, IaC, 쿠버네티스 보안 태세는 **명시적 비목표**입니다. 취약점 매칭과
공유하는 코드가 거의 없습니다.

## 설치

```bash
go install github.com/kun9497/assay/cmd/assay@latest
```

소스에서 빌드:

```bash
git clone https://github.com/kun9497/assay.git
cd assay
make build
```

## 사용법

현재 동작하는 것:

```bash
# 로컬 취약점 데이터베이스 구축 — 권고 데이터를 받아오는 유일한 명령
assay db update

# 데이터베이스에 무엇이 들어 있고 얼마나 최신인지
assay db status

# 레지스트리에서 컨테이너 이미지 스캔
assay scan alpine:3.19

# ...또는 이미 디스크에 있는 것. 둘 다 네트워크를 쓰지 않습니다.
docker save alpine:3.19 -o alpine.tar && assay scan docker-archive:alpine.tar
skopeo copy docker://alpine:3.19 oci:layout && assay scan oci-dir:layout

# CycloneDX SBOM 스캔 (Go, npm, PyPI, Alpine)
assay scan sbom.cdx.json
```

### 타깃이 될 수 있는 것

```bash
assay scan alpine:3.19                # 레지스트리 참조
assay scan docker-archive:app.tar     # `docker save` 타르볼
assay scan oci-dir:./layout           # OCI 레이아웃 디렉터리
assay scan sbom.cdx.json              # CycloneDX SBOM
assay scan ./bin/assay                # Go 바이너리
assay scan ./my-project               # go.mod이 있는 디렉터리
```

접두사 없는 경로는 **내용으로** 분류합니다. 디렉터리면 디렉터리, `debug/buildinfo`가 읽을 수
있으면 Go 바이너리, 최상위에 `bomFormat` 키가 있으면 CycloneDX 문서입니다. 셋 중 무엇도 아닌
파일은 셋을 모두 이름 붙인 오류이지 조용한 추측이 아닙니다. 애초에 경로가 아니면 레지스트리
참조입니다.

`file:`, `dir:`, `sbom:` 접두사가 감지를 재정의합니다 — 기존 `docker-archive:`, `oci-dir:`와
나란히 씁니다. 모든 스캔은 타깃을 무엇으로 분류했는지 stderr에 찍으므로, 잘못된 추측은 헷갈리는
파싱 오류에서 유추하는 것이 아니라 출력에 그대로 보입니다.

*Windows의 Git Bash에서는 접두사가 붙은 절대 경로가 변환되지 않습니다.* `dir:/c/project`*는*
`\c\project`*로 전달됩니다. 상대 경로나 네이티브 경로를 쓰세요:* `dir:C:/project`.

### 바이너리와 디렉터리

**바이너리** 스캔은 `debug/buildinfo`를 읽습니다. 메인 모듈, 링커가 실제로 남긴 모든 의존성,
그리고 툴체인 — 툴체인은 `stdlib`이라는 패키지로 매칭되며 Go 취약점 데이터베이스에 159건의
권고가 있습니다.

**디렉터리** 스캔은 찾은 락파일을 모두 읽습니다 — `go.mod`, `package-lock.json`,
`poetry.lock`. 표준 라이브러리만 쓰고 `go`·`npm`·`pip`을 호출하지 않으므로 오프라인에서 툴체인
없이 동작합니다.

하위 디렉터리도 훑으므로 `frontend/package-lock.json`도 찾습니다. `node_modules`, `vendor`,
`.git`은 건너뛰고 여섯 단계까지만 내려갑니다. **인식했지만 읽지 않은 매니페스트는 이유와 함께
이름을 밝힙니다** — `requirements.txt`는 락파일이 아니고(`Django>=3.2`는 버전이 아니라 제약이며,
범위를 권고의 범위에 맞추면 고정되지 않은 것에 조용히 "취약하지 않음"이라고 답하게 됩니다),
파싱에 실패한 락파일도 사라지지 않고 그 사실을 말합니다.

그 공개가 핵심입니다. 읽히지 않은 매니페스트는 패키지를 만들지 않으므로 요약의 "not evaluated"가
셀 대상이 없습니다. 누락을 드러내려고 만든 바로 그 장치에 누락이 보이지 않는 것입니다 (D26).

`go.mod`은 여전히 모듈이 *요구하는* 것을 보고하며, 그것은 빌드가 링크하는 것과 다릅니다.
이 저장소 기준:

| | 패키지 수 |
|---|---|
| 빌드된 바이너리 | **12** — 메인 모듈, 링크된 의존성 10개, `stdlib` |
| `go.mod` | **11** — 어떤 빌드도 링크하지 않는 `gotest.tools/v3` 포함 |
| `go list -m all` | **52** — 모듈 그래프 전체 |

이 차이는 스캔이 스스로 출력에 밝힙니다:

```
$ assay scan dir:.
scanned dir:. as a directory
go.mod names 11 module(s); this is what was requested, not what a build links
  - scan the built binary for that
```

배포되는 것을 알고 싶으면 바이너리를 스캔하세요. 근거는 D23에 기록되어 있습니다.

### 판정

```bash
assay scan alpine:3.19 --fail-on high         # high 이상 finding이면 1
assay scan alpine:3.19 --fail-on-unknown      # 미평가 finding이 있으면 1
assay scan alpine:3.19 --fail-on-incomplete   # 평가하지 못한 것이 있으면 2
assay scan alpine:3.19 --output json          # stdout에 JSON 문서 하나
assay scan alpine:3.19 --explain CVE-2025-46394
```

`--fail-on`은 `none`, `low`, `medium`, `high`, `critical`을 받습니다. 밴드는 저장된 CVSS
벡터에서 질의 시점에 뽑으므로, 점수 계산이 틀렸을 때 데이터베이스를 다시 만드는 대신 코드만
고치면 됩니다. CVSS v3.1과 v4.0을 모두 채점합니다. v4는 공식이 아니라 270개짜리 룩업 표와 보간
단계를 거치며, 두 채점기 모두 실제 데이터베이스에 있는 모든 벡터로 검증했습니다.

`--fail-on-incomplete`는 1이 아니라 **2**를 반환하고, `--fail-on`과 함께 걸리면 2가 이깁니다.
신뢰할 수 없는 결과가 결과의 내용보다 앞섭니다. 이 플래그는 패키지를 아예 검사하지 못했을 때
*또는* 검사를 끝내지 못했을 때 발동합니다 — 리포트가 요약 줄과 "Not evaluated"에 항상 표시하는
바로 그 두 카운트이므로, 출력이 보여주지 않은 것 때문에 게이트가 걸리는 일은 없습니다.

플래그 이름은 의미가 같은 한 grype를 따릅니다. grype에서 쓰던 것이 여기서도 같은 뜻이라는
의미입니다. 동작이 다른 부분은 발견하도록 방치하지 않고 문서에 명시합니다:

| | grype | assay |
|---|---|---|
| 최하위 밴드 | `negligible` | `none` |
| 미평가 finding | 순서 안에 접어 넣음 | 순서 밖의 `unknown` — `--fail-on-unknown`으로만 |
| 부분 커버리지 | 게이트 없음 | `--fail-on-incomplete`, 종료 코드 2 |
| explain | `grype explain` 서브커맨드 | `scan`의 `--explain <id>` 플래그 |
| 심각도 출처 | CVE alias를 통해 NVD에서 보강 | 저장된 CVSS 벡터만 (D13) |

알아둘 만한 것은 심각도 차이입니다. 이 저장소의 바이너리로 실측했습니다. assay와 grype는
**같은 finding 세 건**을 찾습니다 — 패키지도, 권고 ID도, 수정 버전도 같습니다. 그런데 grype는
그중 둘을 High와 Medium으로 매기고 assay는 `unknown`이라고 합니다. 어느 쪽도 틀리지 않았습니다.
세 권고 모두 OSV 데이터에 심각도 항목이 **하나도 없고**, 그러면 `unknown`이 D13과 D17이 요구하는
답입니다. grype는 각 권고의 CVE alias를 통해 NVD에 닿아 점수를 찾습니다. NVD 보강은 계획이 아니라 기록된 유예 항목입니다 — 그것을
받아들일 메커니즘은 D25와 함께 들어왔고, 비용은 CPE와 purl을 맞추는 일이며, 다시 볼 시점은
`docs/deferred-decisions.md`에 적혀 있습니다.


`--explain`은 권고 자체의 ID뿐 아니라 모든 alias로도 찾습니다. 받은 CVE 번호가 GHSA나 배포판
접두사가 붙은 ID로 기록된 레코드에도 도달합니다.

두 데이터베이스는 흔히 같은 취약점을 서로 다르게 기술합니다. 실제 데이터베이스로 측정한 결과
취약점 그룹 19,715개 중 8,893개(45%)가 레코드를 둘 이상 가지고 있었고, 그중 5,693개는 출처들이
서로 다른 심각도 밴드에 도달했습니다 (D25). 실제로 Django 3.2.12를 스캔하면 취약점
19건이 나오고 그중 15건을 GHSA와 PYSEC가 함께 기술하는데, 그 15건 중 14건은 둘 중 하나만
평가를 매기고 있습니다. finding은 하나만 남기고 나머지를 버리는
대신 모든 소스의 평가를 그대로 유지하며, 게이트는 소스들 중 가장 높은 밴드를 사용합니다 — 한
소스의 `unknown`이 다른 소스가 매긴 `critical`을 희석시키지 않습니다 (D17). 테이블은 finding당
한 행을 유지하되, 소스들의 밴드가 서로 다를 때는 SEVERITY 셀에 `*`를 표시하고 각주로
`--explain <id>`를 가리켜 자세한 내용을 안내합니다. `--output json`은 이긴 하나로 접지 않고
모든 소스를 `ratings` 배열에 담습니다.

### 데이터베이스

권고 데이터는 로컬에 저장되고 스캔과 별개로 갱신됩니다. **스캔은 아무것도 다운로드하지
않습니다.** 데이터베이스가 없거나 스키마가 맞지 않으면 조용히 받아오거나 조용히 빈 결과를
내놓는 대신, 2를 반환하고 `assay db update`를 실행하라고 알려줍니다.

| OS | 위치 |
|---|---|
| Windows | `%LocalAppData%\assay\db\v5\` |
| macOS | `~/Library/Caches/assay/db/v5/` |
| Linux | `~/.cache/assay/db/v5/` |

CI 캐시나 에어갭 환경에서는 `ASSAY_DB_DIR`로 재정의합니다. 경로의 `v5`는 스키마 버전입니다 —
스키마가 바뀌면 제자리에서 마이그레이션하는 대신 새 디렉터리에 다시 빌드합니다. 다만
`ASSAY_DB_DIR`에는 그 성분이 없으므로, 그 경로를 키로 삼은 CI 캐시는 무효화되었어야 할
업그레이드를 넘어 살아남습니다. 업그레이드 후에는 다시 빌드하거나 캐시 키에 assay 버전을
넣으십시오.

Go, npm, PyPI, Alpine으로 빌드하면 **디스크 64 MB에 권고 32,050건**이 담깁니다 — 추정치가
아니라 실제 `db update`를 돌려 측정한 값입니다. 여기까지 오는 데 약 248 MB를 내려받습니다.
OSV는 생태계별로 아카이브 하나씩을 제공할 뿐 서버 측 필터링이 없어서, npm 아카이브의 대부분을
차지하는 악성 패키지 신고는 수집 단계에서 버려지기 때문입니다.

Alpine은 그중 4 MB뿐입니다. OSV가 Alpine을 아카이브 하나로 배포하고 그 안의 레코드가 릴리스를
포함한 생태계 키를 담고 있어서, 한 번 받으면 3.2부터 3.24까지 전부 커버됩니다.

`assay db status`는 provider별로 **업스트림 데이터가 언제 기준인지**를 보고합니다 — 여러분이
언제 내려받았는지가 아닙니다. 3개월 된 스냅샷을 서빙하는 미러가 오늘 아침에 받았다는 이유로
최신처럼 보여서는 안 됩니다.

### 종료 코드

| 코드 | 의미 |
|-----:|---------|
| `0` | 스캔 완료, 게이트에 걸린 것 없음 |
| `1` | 스캔 완료, `--fail-on` 이상의 finding 또는 `--fail-on-unknown` 사용 시 미평가 finding |
| `2` | 스캔을 완료할 수 없었거나, 결과를 신뢰할 수 없음 — `--fail-on-incomplete` 포함 |

둘 이상이 해당되면 **높은 쪽이 이깁니다**: `2` > `1` > `0`. 신뢰할 수 없는 결과가 결과의 내용보다
우선합니다.

CI에서는 "뭔가 찾았다"와 "돌지 못했다"를 구분하는 것이 중요합니다 — 고장 난 스캐너가 깨끗한
빌드처럼 보여서는 안 됩니다. `assay`가 평가할 수 없는 패키지는 건너뛴 개수로 보고되며, 클린 판정에
조용히 섞이지 않습니다.

## 아키텍처

파이프라인은 다섯 개의 인터페이스입니다. 각각 독립적으로 테스트 가능하며, 새 생태계를 지원한다는
것은 `Cataloger` 하나와 `Comparer` 하나를 쓰는 것을 뜻합니다. 나머지는 바뀌지 않습니다.

**굵은 것이 구현된 것이고, 나머지는 설계 목표입니다.**

| 인터페이스 | 책임 | 구현체 |
|---|---|---|
| `Source` | 타깃을 열어 파일 접근 제공, 레이어 출처를 담음 | **레지스트리**, **`docker save` tarball**, **OCI layout**, dir, binary |
| `Cataloger` | 파일 → `[]Package` | **apk**, **os-release**, **cyclonedx**, dpkg, go-mod, go-binary, npm, jar |
| `Store` | 권고 조회 | **bbolt** |
| `Comparer` | 한 생태계 안에서 `Compare(a, b string) (int, error)` | **semver**, **PEP 440**, **apk**, deb, rpm |
| `Provider` | 업스트림 피드 → `[]Advisory` | **OSV**, KISA |

데이터베이스는 스캔과 직교합니다. `Provider`가 `assay db update`를 통해 채우고, 스캔은 읽기만
하며, 오래되었거나 없는 데이터베이스를 뒤에서 고쳐주지 않습니다. 오프라인 동작이 플래그가 아니라
기본값인 이유가 이것입니다 — 권고 데이터를 조용히 받아오는 스캐너는 결과를 재현할 수도 감사할
수도 없습니다.

권고는 **OSV 형태**로 저장됩니다 — `affected[].ranges[]`가 `introduced` / `fixed` 이벤트를
담습니다. OSV가 주 provider이며 거의 그대로 통과하고, 다른 소스는 같은 형태로 정규화됩니다. 검증된
정규화 대상을 재사용하는 편이 새로 만드는 것보다 낫고, **스키마를 우리가 소유한다는 점이 애초에
KISA 데이터를 넣을 수 있게 합니다.**

레코드는 **무손실로** 저장하고 파생값은 조회 시점에 계산합니다 — 심각도 밴드는 빌드 시점에 박아
넣는 대신 저장된 CVSS 벡터에서 뽑습니다. 아직 필요 없는 필드도 저장합니다. 나중에 하나 추가하려면
데이터베이스를 다시 빌드해야 하기 때문입니다.

수집 단계에서 버리는 것이 둘 있습니다. **철회된 권고(withdrawn)** — 철회된 권고가 계속 finding을
만들어내면 그냥 오탐이기 때문입니다. 그리고 **악성 패키지 신고(`MAL-*`)** — 덜 중요해서가 아니라
성격이 다른 finding 클래스이기 때문입니다. 심각도가 없고, 수정 버전을 지목하지 않으며, 심각도
밴드가 아니라 "지금 제거하고 침해를 가정하라"를 요구합니다. 원본 데이터의 약 80%를 차지하기도
합니다. 제대로 지원하려면 무엇이 필요한지는
[`docs/deferred-decisions.ko.md`](docs/deferred-decisions.ko.md)에 있습니다.

**전체 권고의 절반가량에는 심각도가 아예 없습니다.** 이것을 "low"로 떨어뜨리면 데이터의 공백이
빌드 통과로 바뀌는데, 종료 코드 체계가 막으려는 것이 정확히 그 실패입니다. 그래서 `unknown`은
`low < medium < high < critical` 순서의 맨 아래가 아니라 **그 바깥에 있는 독립 밴드**입니다:

- unknown finding은 **항상 보고됩니다.** 임계값은 무엇이 빌드를 실패시킬지를 정할 뿐, 무엇이
  출력에 나타날지는 정하지 않습니다. unknown 개수는 항상 요약에 포함됩니다.
- unknown은 `--fail-on <band>` 만으로는 **트립하지 않습니다.** 전체 권고의 절반이 미평가인
  상황에서 그렇게 하면 모든 스캔이 실패합니다.
- `--fail-on-unknown`이 이를 **명시적으로** 게이팅합니다. 위 두 규칙만으로는 평가되지 않은
  critical 취약점이 여전히 0으로 통과하기 때문입니다 — 출력에는 찍히지만, 통과입니다.

### 나중에 틀리기 쉬운 세 가지

- **배포판 패키지는 생태계 키에 릴리스를 포함합니다** — `Alpine`이 아니라 `Alpine:v3.19`.
  수정 버전이 릴리스마다 다르므로 릴리스가 조회 키의 일부입니다.
- **배포판은 패키지가 아니라 타깃에 속합니다.** *이미지*가 Alpine 3.19인 것이지 그 안의 패키지가
  그런 게 아닙니다. `Target.Distro`는 `/etc/os-release`에서 한 번 읽어 내부의 모든 OS 패키지에
  적용됩니다.
- **패키지는 자신의 소스 패키지를 담습니다.** 배포판 권고는 *소스* 패키지 기준으로 작성되지만
  설치된 것은 *바이너리* 패키지입니다 — 소스 `openssl`에 대한 권고는 `libssl1.1`을 조회해서는
  절대 찾을 수 없습니다. 이걸 놓치면 **미탐**이 발생하는데, 미탐은 조용합니다. 그 조회를 위해
  `Package.Source`가 존재합니다. 이는 Debian과 RHEL뿐 아니라 **Alpine에도 적용됩니다** — Alpine의
  OSV 레코드는 purl에 `?arch=source`를 담고 있습니다.

### 왜 버전 비교를 생태계별로 하는가

버전 비교는 보편적이지 않습니다 — Debian의 epoch, RPM의 release 순서, semver의 pre-release
우선순위, Maven의 정렬 규칙이 서로 어긋납니다. 단일 `compareVersions` 함수는 이 설계가 피하려는
바로 그 버그 공장이며, `Comparer`가 생태계별인 이유입니다.

`Comparer`가 순서만이 아니라 에러도 반환하는 이유는, 실제 시스템의 버전 문자열이 때때로 형식이
깨져 있고 **파싱 불가능한 버전을 "취약하지 않음"으로 처리하면 그것이 미탐이기 때문입니다.**

## 로드맵

아키텍처 계층이 아니라 **동작하는 경로**를 따라 잘랐습니다 — 계층 하나만으로는 실행할 수 없고,
실행할 수 없는 설계는 검증할 수 없습니다.

**① 매칭 코어** ✅ — CycloneDX SBOM → OSV 기반 store → matcher → table 출력. Go, npm, PyPI 대상.
핵심 타입과 인터페이스가 여기서 확정됩니다.

- [x] 핵심 타입, `Store` / `Comparer` / `Provider` 인터페이스
- [x] OSV provider와 로컬 bbolt store
- [x] `assay db update`, `assay db status`
- [x] CycloneDX SBOM 수용
- [x] 생태계별 버전 비교와 범위 매칭
- [x] table 출력

**②a distro 매칭** ✅ — SBOM에서 Alpine 패키지 매칭: 릴리스 포함 생태계 키, 소스 패키지
간접 참조, apk 버전 정렬.

- [x] apk `Comparer` — apk-tools 자체 테스트 벡터 738건으로 검증
- [x] `Target.Distro`와 `Alpine:vX.Y` 생태계 키
- [x] `Package.Source` 간접 매칭
- [x] Alpine 권고 수집

**②b 컨테이너** ✅ — 레지스트리 pull, 레이어 추출, whiteout, `/etc/os-release`,
`/lib/apk/db/installed`.

- [x] 레지스트리·`docker save` tarball·OCI layout에서 이미지 읽기
- [x] whiteout과 심볼릭 링크를 처리하는 레이어 순회
- [x] `/etc/os-release`와 `/lib/apk/db/installed` 카탈로거

Docker 데몬은 의도적으로 소스에서 제외했습니다. import하면 링크되는 의존성이 모듈 9개에서
27개로 늘어나고, 로컬에 이미 있는 이미지는 `docker save`로 `assay`에 넘길 수 있습니다.

**③ 파일시스템과 바이너리 타깃** — ②에도 ④에도 의존하지 않으므로 어디든 끼워 넣을 수 있습니다.

- [x] `debug/buildinfo`를 통한 Go 바이너리 스캔, 툴체인을 `stdlib`으로 포함
- [x] 디렉터리 스캔 (Go 모듈, `go.mod`만 — 툴체인도 네트워크도 쓰지 않음)

**⑥ 디렉터리 스캔이 읽지 않는 것** — D26이 측정한 공백입니다. `go.mod`과
`package-lock.json`이 함께 있는 디렉터리가 Go 패키지만 보고하고 `0 not evaluated`라고 말한 뒤
0을 반환하는 동안 finding 24건이 언급조차 되지 않았습니다. **완료.**

- [x] `package-lock.json`과 `poetry.lock` cataloger, 제한된 하위 탐색 위에서
- [x] 인식했지만 읽지 않은 매니페스트를 이름과 이유와 함께 밝히기 (D26)
- [ ] `requirements.txt` — 고정되지 않은 제약에 대한 별도 결정이 필요

**④ 판정과 출력** — 종료 코드 1이 처음으로 도달 가능해지는 지점입니다. **완료.**

- [x] `--fail-on` 심각도 게이팅, `--fail-on-unknown`과 `--fail-on-incomplete`
- [x] CVSS v3.1과 v4.0 채점, 실제 데이터베이스의 모든 벡터로 검증
- [x] 스키마 버전과 골든 파일 테스트를 갖춘 JSON 출력
- [x] explain 모드 — 특정 finding의 매칭 근거 출력
- [x] 출처별 평가 — finding이 모든 데이터베이스의 평가를 유지하고, 게이트는 그중 가장 높은
      것을 취함 (D25)
- [ ] SARIF 출력 (`docs/deferred-decisions.md` 참조)
- [ ] 두 번째 평가 출처로서의 NVD (`docs/deferred-decisions.md` 참조)

**⑤ KISA 보강** — 매칭된 finding에 한국어 설명과 심각도를 결합합니다.
**보류: 2026-08-02 조사 결과 데이터가 이를 뒷받침하지 않습니다.**

KNVD가 발행한 취약점 레코드는 전체 **173건**이고, 최근 10건은 전부 국내 상용 소프트웨어입니다 —
ipTIME 공유기, 한컴오피스, 알집, DVR, 그룹웨어. Go·npm·PyPI·Alpine 패키지는 하나도 없어서,
컨테이너 이미지나 소스 트리에 대한 CVE ID 조인은 사실상 걸리지 않습니다. 레코드 자체는 잘
구조화되어 있습니다 — CVE ID, CVSS 점수와 등급, 영향/해결 버전, 한국어 설명 — 그러므로 장애물은
형식이 아니라 대상 영역입니다. 접근과 라이선스도 불리합니다. 문서화된 RSS 피드 둘은 최신 10건만
반환하고, 사이트는 공공누리 표시 없이 모든 권리 보유로 표기되어 있습니다. 자세한 내용은 로드맵에
있습니다.

- [ ] KNVD provider와 보강 조인 — 타깃이 호스트나 워크스테이션으로 넓어지면 재검토

정확성은 매 단계 **grype와의 대조 테스트**로 검증합니다. 데이터 소스가 다르므로 완전한 일치는
기대하지 않지만, **큰 차이가 나면 우리 매처가 틀린 것입니다.** 슬라이스 ①은 대조한 두 SBOM 모두에서
집합이 정확히 일치했습니다:

| 대상 | assay | grype | 미탐 | 오탐 |
|---|---:|---:|---:|---:|
| PyPI SBOM (대소문자 혼용 이름) | 32 | 32 | 0 | 0 |
| Go 모듈 SBOM | 4 | 4 | 0 | 0 |
| `alpine:3.19` SBOM | 10 | 10 | 0 | 0 |

이미지를 직접 읽는 경로는 grype가 아니라 **SBOM 경로와 대조**합니다. 그래야 데이터베이스·매처·
비교기가 고정되고, 차이가 나면 그것이 전적으로 우리 것이기 때문입니다. 같은 이미지에 이르는 네
경로가 정확히 일치합니다:

| 경로 | findings |
|---|---:|
| syft SBOM | 10 |
| 레지스트리 pull | 10 |
| `docker save` tarball | 10 |
| OCI layout 디렉터리 | 10 |

컴포넌트 총계는 1 차이 나는 것이 정상입니다. syft가 `operating-system` 컴포넌트를 하나 더
내보내고 SBOM 경로가 그것을 세었다가 제외하는데, 이미지를 직접 읽으면 그런 항목이 없습니다.

grype의 **distro 네임스페이스** 발견과 비교한 것입니다. grype의 `nvd:cpe` 매칭은 같은
이미지에서 11건 더 나오지만 `assay`가 구현하지 않는 CPE 휴리스틱에서 오므로, 합쳐서 세면
비교가 아니라 어느 한쪽을 좋아 보이게 만드는 일이 됩니다.

Alpine 발견 10건 중 **6건**은 소스 패키지를 거쳐야만 도달합니다. `busybox-binsh`,
`ssl_client`, `musl-utils`는 각각 `busybox`와 `musl`에 대해 작성된 권고를 지고 있습니다. 그
간접 참조가 없으면 **발견의 절반 이상이** 조용한 미탐이 되고, 그래서 이것이 D8입니다.

바이너리 스캔은 해당 언어가 무엇을 남기느냐에 전적으로 달려 있습니다. Go와 Java는 의존성 목록을
복원할 만큼의 메타데이터를 담고, Rust는 `cargo-auditable`로 빌드된 경우에만 가능하며, 스트립된
C/C++는 신뢰할 만한 것을 남기지 않습니다. 지원 여부는 카테고리로 약속하지 않고 언어별로
판단합니다.

눈에 띄는 누락들 — Debian·RHEL 지원, VEX 억제, 사전 빌드된 데이터베이스 아티팩트, 데이터베이스
나이 강제 — 은 의도된 것입니다.
[`docs/deferred-decisions.ko.md`](docs/deferred-decisions.ko.md)에 무엇을 왜 미뤘는지, 무엇이
재검토를 촉발해야 하는지, 어떤 사전 작업이 이미 되어 있는지가 기록되어 있습니다.

## 기여

이슈와 PR을 환영합니다. 기능을 제안하기 전에
[`docs/deferred-decisions.ko.md`](docs/deferred-decisions.ko.md)를 확인해 주십시오 — 눈에 띄는
빈틈은 대체로 의도된 것이고, 무엇이 그 결정을 바꿀 수 있는지가 적혀 있습니다.

## 고지

이것은 독립적인 개인 프로젝트입니다. 어떤 고용주의 제품과도 제휴·보증 관계가 없고 파생물도
아니며, 어떠한 종류의 보증도 제공하지 않습니다. 이 도구를 취약점 정보의 유일한 출처로 삼지
마십시오.

## 라이선스

[Apache License 2.0](LICENSE)
