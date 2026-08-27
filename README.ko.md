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

🚧 **활발히 개발 중입니다. 배포판 계열 15개와 언어 생태계 8개가 끝에서 끝까지 스캔되며,
[로드맵](#로드맵) 체크박스가 가장 확실한 목록입니다.**

`assay db update`가 배포된 데이터베이스를 받아옵니다 — OSV의 언어 생태계(Go, npm, PyPI,
crates.io, Maven, RubyGems, NuGet, Packagist)와 함께 Alpine, Debian, Ubuntu, Rocky, Alma;
fix 상태를 담은 Red Hat의 CSAF VEX; Amazon의 ALAS(core와 AL2 extras); Oracle의 ELSA;
Fedora의 Bodhi; 그리고 SUSE의 CSAF VEX까지 — 중앙에서 빌드해 매일 갱신하고 NVD 등급까지
조인한 것입니다 — 그리고 `assay scan`이 컨테이너 이미지, Go 바이너리, 디렉터리, SBOM을
거기에 매칭합니다. 컨테이너 이미지를 직접 읽으므로 syft는 필요 없습니다. 실제 대상에서
grype와 동일한 finding을 보고합니다: 개수만 같은 것이 아니라 CVE 집합이 같습니다.

배포판 패키지는 **소스 패키지를 거쳐** 매칭됩니다. `openssl` 권고가 설치된 `libssl3`에
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

**개인 프로젝트이고, 취약점 스캐너가 어떻게 동작하는지를 끝에서 끝까지 직접 만들어보며 배우려고
시작했습니다.** 기존 스캐너들은 훌륭하고 충분히 검증되어 있습니다. 프로덕션에서는 그것들을 쓰십시오.

출발점은 국내 취약점 데이터였습니다 — KISA/KNVD를 일급 provider로 삼는 것. 첫 조사는 성립하지
않는다고 했지만, 틀린 게시판을 잰 결과였습니다. KNVD 자체 공개는 국내 상용 소프트웨어 173건이고,
**보안공지**는 Apache, OpenSSL 같은 소프트웨어의 CVE를 키로 합니다. **그것이 이제 만들어져
있습니다**(슬라이스 ⑤). KISA는 독립 매칭 소스가 아니지만 CVE 기반 보강 조인은 되고, 2026-08-06
라이브 walk가 **공지 2,971건**에서 **서로 다른 CVE 18,524개**를 읽었습니다. 다만 그것은 이동하지
못합니다. KISA의 이용 조건은 그 데이터로 스캔하는 것은 허용하되 재배포는 제한하므로, 보강은
로컬에서 만들어지고 배포 아티팩트에서는 벗겨집니다(D29).

코드가 실제로 좇는 것은 그보다 좁고, 지금까지는 유지되고 있습니다. **자신 있게 틀린 답을 내지
않는 것.** 모든 finding이 그것을 만들어낸 근거를 함께 전달합니다 — 어떤 범위, 어떤 comparer, 어떤
비교 결과였는지. 평가하지 못한 것은 전부 세어서 이름을 밝힙니다. 스캔은 취약점 데이터를 절대
받아오지 않습니다.

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
# 배포된 취약점 데이터베이스 받아오기 — 평상시 경로, 시간이 아니라 초 단위
assay db update

# ...또는 직접 빌드합니다. KISA의 한국어 공지를 얻는 유일한 방법입니다.
# 기본으로 켜져 있고(D37), 배포되는 것에서는 벗겨집니다(D29).
assay db build --seed "$(assay db ref)"

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

데이터베이스 쪽에서 네트워크를 건드리는 명령은 `assay db update`, `assay db build`,
`assay db push` 셋뿐입니다 — **스캔 자체는 여전히 네트워크를 전혀 쓰지 않습니다**, 사용자가
지목한 원격 **대상**을 받아오는 것을 빼면요(D14). `assay db build`는 업스트림 provider들로부터
직접 빌드하고, `assay db push`는 그 결과를 배포합니다. 둘 다 이제는 배포자의 명령이지 평상시
경로가 아닙니다 — 누가 어느 쪽이 필요하고 왜인지는 아래 [데이터베이스](#데이터베이스) 절을
보세요.

### 타깃이 될 수 있는 것

```bash
assay scan alpine:3.19                # 레지스트리 참조
assay scan docker-archive:app.tar     # `docker save` 타르볼
assay scan oci-dir:./layout           # OCI 레이아웃 디렉터리
assay scan sbom.cdx.json              # CycloneDX SBOM
assay scan ./bin/assay                # Go 바이너리
assay scan ./my-project               # go.mod이 있는 디렉터리
assay scan ./app.jar                  # Java 아카이브(신원은 pom.properties에서)
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
`npm-shrinkwrap.json`, `yarn.lock`(v1), `poetry.lock`, `Pipfile.lock`, `uv.lock`, `Cargo.lock`,
`Gemfile.lock`, `composer.lock`, `packages.lock.json`. 표준 라이브러리만 쓰고
`go`·`npm`·`pip`·`uv`·`cargo`를 호출하지 않으므로 오프라인에서 툴체인 없이 동작합니다.

트리에서 찾은 모든 `*.jar`/`*.war`도 함께 읽습니다 — 신원은 `pom.properties` 항목에서 가져오며,
중첩되거나 shade된 아카이브도 포함합니다; `pom.properties`가 없는 jar는 세어서 이름을 밝힐 뿐,
파일명에서 추측하지 않습니다.

하위 디렉터리도 훑으므로 `frontend/package-lock.json`도 찾습니다. `node_modules`, `vendor`,
`.git`은 건너뛰고 여섯 단계까지만 내려갑니다. **인식했지만 읽지 않은 매니페스트는 이유와 함께
이름을 밝힙니다** — `requirements.txt`는 락파일이 아니고(`Django>=3.2`는 버전이 아니라 제약이며,
범위를 권고의 범위에 맞추면 고정되지 않은 것에 조용히 "취약하지 않음"이라고 답하게 됩니다),
파싱에 실패한 락파일도 사라지지 않고 그 사실을 말합니다.

`pnpm-lock.yaml`과 yarn berry 락파일은 인식하고 **exit 2**를 냅니다 (D61). 읽으려면 YAML 파서가
필요하고 그건 이 프로젝트가 아직 받지 않은 세 번째 직접 의존성입니다. 받기
전까지, 락파일이 이것뿐인 저장소는 의존성을 하나도 보지 않은 것이고 그건 깨끗한 결과가 아니라 믿을
수 없는 결과입니다. yarn berry는 시도하지 않고 감지합니다. v1 파서가 berry 파일에서 실패하지 않고
성공한 뒤 아무것도 못 찾기 때문입니다.

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
assay scan alpine:3.19 --fail-on-incomplete=target  # ...그 원인이 내 데이터일 때만
assay scan ubi8:8.9 --fail-on-unfixable             # 아무도 못 고치는 finding이면 exit 1
assay scan ubi8:8.9 --fail-on-unfixable=wont-fix    # ...그중 영영 안 고쳐질 것만
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
| 부분 커버리지 | 게이트 없음 | `--fail-on-incomplete[=any\|target]`, 종료 코드 2 |
| explain | `grype explain` 서브커맨드 | `scan`의 `--explain <id>` 플래그 |
| 심각도 출처 | 항상 CVE alias를 통해 NVD | 저장된 CVSS 벡터 + (활성화 시) NVD |

알아둘 만한 것은 심각도 차이였고, 그것을 메우는 것이 슬라이스 ⑦의 목적이었습니다. 이 저장소의
바이너리로 실측했습니다. assay와 grype는 **같은 finding 세 건**을 찾습니다 — 패키지도, 권고 ID도,
수정 버전도 같습니다. 그런데 grype는 그중 둘을 High와 Medium으로 매기고 assay는 `unknown`이라고
했습니다. 어느 쪽도 틀리지 않았습니다. 세 권고 모두 OSV 데이터에 심각도 항목이 **하나도 없고**,
그러면 `unknown`이 D13과 D17이 요구하는 답이며, grype는 각 권고의 CVE alias를 통해 NVD에 닿아
점수를 찾습니다.

데이터베이스를 만들 때 `NVD_ENABLE=1`을 주면 assay도 이제 같은 둘을 high(7.8)와 medium(5.3)으로
매기고, 한쪽을 다른 쪽으로 **대체하지 않고 둘 다** 보고합니다.

```
severity: high (7.8)   [highest of 2 sources]
  GO     GO-2026-4970    unknown          fixed 1.26.5
  NVD    CVE-2026-39822  high (7.8)       fixed -  https://nvd.nist.gov/vuln/detail/CVE-2026-39822
```

남은 차이는 세 번째 finding이고, 그것은 의도된 것입니다. CVE가 없어 아무것도 조인되지 않으므로
`unknown`으로 남습니다 — 세어지고, 보고되고, `--fail-on-unknown`으로만 게이팅됩니다(D17). NVD는
패키지가 매칭되는지 **여부**는 결코 정하지 않고 CVE가 얼마나 나쁜지만 말합니다(D27). 권고와
매칭된 범위와 수정 버전은 언제나 assay가 실제로 비교한 레코드에서 옵니다.


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
| Windows | `%LocalAppData%\assay\db\v9\` |
| macOS | `~/Library/Caches/assay/db/v9/` |
| Linux | `~/.cache/assay/db/v9/` |

CI 캐시나 에어갭 환경에서는 `ASSAY_DB_DIR`로 재정의합니다. 경로의 `v9`는 스키마 버전입니다 —
스키마가 바뀌면 제자리에서 마이그레이션하는 대신 새 디렉터리에 다시 빌드합니다. 다만
`ASSAY_DB_DIR`에는 그 성분이 없으므로, 그 경로를 키로 삼은 CI 캐시는 무효화되었어야 할
업그레이드를 넘어 살아남습니다. 업그레이드 후에는 다시 빌드하거나 캐시 키에 assay 버전을
넣으십시오.

Go, npm, PyPI, Alpine으로 빌드하면 **디스크 64 MB에 권고 32,050건**이 담깁니다 — 추정치가
아니라 실제 `db build`를 돌려 측정한 값입니다. 여기까지 오는 데 약 248 MB를 내려받습니다.
OSV는 생태계별로 아카이브 하나씩을 제공할 뿐 서버 측 필터링이 없어서, npm 아카이브의 대부분을
차지하는 악성 패키지 신고는 수집 단계에서 버려지기 때문입니다.

Alpine은 그중 4 MB뿐입니다. OSV가 Alpine을 아카이브 하나로 배포하고 그 안의 레코드가 릴리스를
포함한 생태계 키를 담고 있어서, 한 번 받으면 3.2부터 3.24까지 전부 커버됩니다.

`assay db status`는 provider별로 **업스트림 데이터가 언제 기준인지**를 보고합니다 — 여러분이
언제 내려받았는지가 아닙니다. 3개월 된 스냅샷을 서빙하는 미러가 오늘 아침에 받았다는 이유로
최신처럼 보여서는 안 됩니다.

`db build`는 설정된 평가 출처 — 오늘은 NVD (D27) — 도 권고 provider 바로 뒤에 실행하여 그
CVSS 의견을 같은 데이터베이스에 기록합니다. 스캔 시점에는 아무것도 가져오지 않습니다
(D14). `assay db status`는 하나 이상의 CVE를 평가한 출처를 `databases:`와 같은 모양의
`ratings:` 줄에 나열합니다. `NVD_API_KEY`를 설정하면 NVD 요청 속도 제한이 10배 올라갑니다 —
선택 사항이며 필수가 아닙니다. 키가 없어도 빌드는 NVD를 동기화하되, 더 느릴 뿐입니다.

**배포 (D28).** 데이터베이스는 이제 하루에 한 번 중앙에서 빌드되어 `ghcr.io/kun9497/assay-db`에
OCI 아티팩트로 배포되며, 태그는 스키마 버전입니다 — `assay db ref`가 주어진 바이너리가 읽는
태그를 정확히 출력하므로, 오래된 바이너리는 잘못 해석할 데이터베이스 대신 옛 태그에 대한 깔끔한
"찾을 수 없음"을 받습니다.

- **`assay db update [--from <ref>]`** — 배포된 아티팩트를 받아옵니다. 평상시 경로입니다. 시간이
  아니라 초 단위이고, CI가 실행해야 할 것도 이것입니다. `--from`은 기본값 대신 미러나 고정된
  다이제스트를 가리킵니다.
- **`assay db build [--seed <ref>]`** — 업스트림 provider들로부터 직접 빌드합니다. 배포자의
  명령이고, `ghcr.io`를 신뢰하는 대신 독립적으로 빌드하고 싶은 사람을 위한 것이기도 합니다.
  Go, npm, PyPI, Alpine, NVD(`NVD_ENABLE=1`)를 전부 도는 전체 패스는 약 **7시간**이 걸립니다
  (측정값, 슬라이스 ⑦ 참고) — `--seed <ref>`는 전체 패스를 반복하는 대신 이전에 배포된
  아티팩트 위에 쌓습니다. **rating**은 가져오지만 **advisory**는 소스에서 매번 다시 빌드하므로,
  업스트림이 나중에 철회하는 advisory는 seed 안에서 영원히 살아남는 대신 여전히 사라질 수
  있습니다. seeding 덕분에 매일 도는 배포(`.github/workflows/db-publish.yml`)가 GitHub
  Actions의 6시간 잡 상한 안에 들어갑니다. 이전 아티팩트에서 seed하고 그 위에 NVD 변경분 3일치를
  쌓을 뿐입니다. 읽을 수 없는 `--seed` 참조는 곧바로 빌드를 실패시킵니다 — 2를 반환하며, 빈
  상태로 조용히 넘어가는 일은 없습니다.
- **`assay db push <ref>`** — 로컬 데이터베이스를 OCI 아티팩트로 배포합니다. 성공하면
  `<name>@<digest>`를 출력합니다.

**로컬 전용 보강 (D29).** `db build`에 `KISA_ENABLE=1`을 주면 KISA의 한국어 보안공지도 받아와
CVE로 매칭된 finding에 결합합니다 — 제목, 요약, 링크일 뿐 매칭 소스도 심각도도 아닙니다(D3).
KISA 사이트는 공공누리 표시 없이 모든 권리를 보유하고 있으며, 이는 그 데이터를 재배포하는 것을
제한하지 그것으로 스캔하는 것을 제한하지 않습니다 — 그리고 `db push`는 재배포입니다. 그래서
`db push`는 스테이징된 복사본에서 `enrichment` 버킷을 비운 다음, 그 복사본의 *라이브* 데이터를 새
파일로 복사해 배포할 파일을 만듭니다 — 버킷을 지우면 그 레코드는 해제된 페이지에 그대로 남고,
아티팩트는 파일 전체이기 때문입니다 — 그래서 `db update`는 그것을 결코 전달하지 않습니다.
한국어 텍스트를 원하는 사람은 직접 `db build`를 돌려야 합니다. 라이선스 문제가 풀리면 이를
되돌리는 것은 보강이 어디 사는지를 옮기는 일이 아니라 그 벗겨내기를 지우는 일입니다.

이 중 어느 것도 스캔이 하는 일을 바꾸지 않습니다. **스캔은 여전히 아무것도 받아오지
않습니다**(D14). 데이터베이스 쪽에서 네트워크를 건드리는 명령은 `db update`, `db build`,
`db push` 셋뿐입니다.

**첫 아티팩트 부트스트랩하기.** 매일 도는 워크플로는 이미 존재하는 아티팩트에서 seed하므로,
맨 처음 하나는 사람이 손으로 한 번 만듭니다.

```bash
NVD_ENABLE=1 NVD_SINCE_DAYS=30 assay db build   # 27분, 측정값
assay db status                                 # `ratings: NVD (…)`가 0이 아닌지 확인
assay db push ghcr.io/kun9497/assay-db:v8       # 압축 약 6.8 MB
```

**첫 패스는 범위를 제한하세요. 전체 피드로 가지 마십시오.** 제한 없는 빌드는 약 7시간이고 재개
지점이 없습니다 — `db build`는 임시 데이터베이스를 만들어 마지막에만 설치하므로, 5시간째의 실패가
5시간을 통째로 버립니다. 넓은 창으로 네 번 그렇게 실패한 뒤 30일 창이 27분 26초에 rating 23,433건으로
성공했습니다.

`NVD_SINCE_DAYS=120`도 보이는 것 같은 절충이 아닙니다. NVD가 재채점·참조 추가로 레코드를 계속
건드려서, 120일치 *수정분*이 37만 2,628건 피드의 대부분을 덮고 창이 없는 것과 비용이 거의 같습니다.

**오래된 등급 백필**(D65)은 창에 *끝*이 생기는 유일한 지점입니다. `NVD_UNTIL_DAYS`가 그 끝을
닫으므로, 전체 피드를 경계가 있는 슬라이스들로 나눠 거꾸로 훑을 수 있습니다. 각 실행은 발행된
아티팩트에서 seed하고 차례로 push합니다 — 아티팩트가 체크포인트이므로, 실패한 슬라이스는 전체
패스가 아니라 슬라이스 하나만 잃습니다.

```bash
# 각 슬라이스: [now-SINCE, now-UNTIL], 120일씩 뒤로 훑습니다.
# --ratings-only(D66)는 시드의 advisory를 그대로 가져오고 NVD 창만 다시 돌리므로,
# 슬라이스 비용은 그 자체의 NVD 시간뿐이고 전체 재빌드가 아닙니다.
NVD_ENABLE=1 NVD_SINCE_DAYS=240 NVD_UNTIL_DAYS=120 assay db build --seed ghcr.io/kun9497/assay-db:v8 --ratings-only
assay db push ghcr.io/kun9497/assay-db:v8
NVD_ENABLE=1 NVD_SINCE_DAYS=360 NVD_UNTIL_DAYS=240 assay db build --seed ghcr.io/kun9497/assay-db:v8 --ratings-only
assay db push ghcr.io/kun9497/assay-db:v8
# ...db status의 COVERED 범위가 피드의 시작점에 닿을 때까지 반복합니다
```

CI에서는 `gh workflow run db-backfill.yml -f since_days=240 -f until_days=120`가 슬라이스 하나를
실행합니다.

슬라이스는 순서대로 실행하세요. 커버리지는 슬라이스가 이미 커버된 범위에 *닿을* 때만 과거로
확장됩니다 — 순서를 벗어나면 rating은 그대로 들어가지만 주장하는 커버리지는 그 자리에 머뭅니다.
구멍을 건너뛴 주장은 데이터베이스가 조각만 가진 구간을 전부 커버한다고 말하는 셈이기 때문입니다.

좁아진 커버리지는 가정하지 않고 공개합니다. `db status`가 `COVERED` 열에 범위를 출력하므로 30일짜리
데이터베이스가 완전한 것처럼 보일 수 없습니다. push 전에 `ratings:`를 확인하세요 — rating이 0인
아티팩트는 이후 모든 델타 빌드의 seed가 되고, 매일 도는 실행이 빠진 것을 영영 채우지 못합니다.

그 뒤로는 예약된 워크플로가 알아서 최신 상태를 유지합니다.

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
| `Source` | 타깃을 열어 파일 접근 제공, 레이어 출처를 담음 | **레지스트리**, **`docker save` tarball**, **OCI layout**, **dir**, **binary** |
| `Cataloger` | 파일 → `[]Package` | **apk**, **os-release**, **cyclonedx**, **dpkg**, **rpmdb**, **go-mod**, **go-binary**, **npm**, **yarn**, **pypi 락파일들**, **cargo**, **gem**, **composer**, **nuget 락파일**, **jar** |
| `Store` | 권고 조회 | **bbolt** |
| `Comparer` | 한 생태계 안에서 `Compare(a, b string) (int, error)` | **semver**, **PEP 440**, **apk**, **deb**, **rpm**, **gem**, **composer**, **nuget**, **maven** |
| `Provider` | 업스트림 피드 → `[]Advisory` | **OSV**, **Red Hat CSAF VEX** |

`Provider` 옆에는 두 인터페이스가 더 있습니다. `Provider` 안에 넣지 않은 이유는 이 둘이 finding에
붙이는 것이 `Advisory`가 아니기 때문입니다. `Annotator`는 assay가 이미 매칭한 CVE의 점수를 매기고
(**NVD**, D27), `Enricher`는 그것을 산문으로 설명합니다(**KISA**, D29). 어느 쪽도 패키지가
매칭되는지 여부를 정하지 못합니다. 둘 다 `Provider`가 이미 만들어낸 판정에 덧붙을 뿐입니다.

데이터베이스는 스캔과 직교합니다. `Provider`가 `assay db build`를 통해 채우고, `assay db
update`는 배포된 결과를 받아오며(D28), 스캔은 읽기만 하며, 오래되었거나 없는 데이터베이스를
뒤에서 고쳐주지 않습니다. 오프라인 동작이 플래그가 아니라
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

**③ 파일시스템과 바이너리 타깃** ✅ — ②에도 ④에도 의존하지 않으므로 어디든 끼워 넣을 수 있습니다.

- [x] `debug/buildinfo`를 통한 Go 바이너리 스캔, 툴체인을 `stdlib`으로 포함
- [x] 디렉터리 스캔 (Go 모듈, `go.mod`만 — 툴체인도 네트워크도 쓰지 않음)

**⑥ 디렉터리 스캔이 읽지 않는 것** ✅ — D26이 측정한 공백입니다. `go.mod`과
`package-lock.json`이 함께 있는 디렉터리가 Go 패키지만 보고하고 `0 not evaluated`라고 말한 뒤
0을 반환하는 동안 finding 24건이 언급조차 되지 않았습니다.

- [x] `package-lock.json`과 `poetry.lock` cataloger, 제한된 하위 탐색 위에서
- [x] 인식했지만 읽지 않은 매니페스트를 이름과 이유와 함께 밝히기 (D26)
- [x] `yarn.lock`(v1)·`Pipfile.lock`·`npm-shrinkwrap.json` cataloger (D61). yarn의 별칭
      항목은 로컬 이름이 아니라 실제 설치된 패키지로 해석됩니다
- [x] `pnpm-lock.yaml`과 yarn berry는 인식하고 이름을 부르고 2를 냅니다 (D61)
- [x] `Cargo.lock`과 OSV crates.io 아카이브 (D62) — 레코드 2,725건, 그중 62%가 등급을 담고
      있으며, 키(`crates.io`)가 purl 타입(`cargo`)과 다른 첫 생태계
- [x] `uv.lock` (D63). TOML 리더가 필요하다던 D61의 주장을 정정합니다 — uv 자신의 락파일에서
      패키지 77개 중 77개, `Cargo.lock`과 스캐너를 공유해 둘이 어긋날 수 없습니다
- [x] Maven, RubyGems, NuGet, Packagist를 OSV에서 (D68) — 정본 소스 comparer 네 개, Drupal
      contrib 폴드, 그리고 끝에서 끝까지 동작하는 SBOM 스캔; lockfile cataloger는 다음
      슬라이스
- [x] `Gemfile.lock`, `composer.lock`, `packages.lock.json` cataloger (D69) — 이제 checkout도
      SBOM이 매칭되는 모든 곳에서 매칭됩니다; Maven은 락파일이 없고, 그 경로는 jar 스캔입니다
- [x] jar와 fat-jar 스캔 (D70) — 아카이브 안의 모든 `pom.properties`, 깊이 3까지 중첩
      탐색; 합성 Spring Boot jar 안에서 log4shell을 끝에서 끝까지 찾아냄; 파일명 추측은
      거부
- [x] Rocky Linux를 OSV에서 (D71) — Rocky Linux:8/9/10로 키를 잡고, 네이티브 CVSS 84%,
      module 빌드는 버려서 셈; RPM계 다섯 결정을 기록
- [x] AlmaLinux를 OSV에서 (D72) — AlmaLinux:8/9/10으로 키를 잡고, CVSS는 어디에도 0%라서
      요약문의 심각도 단어("Important: openssh security update")를 무손실로 저장하고
      밴드화합니다; CVE는 오직 `related`에만 있어 배포판이 직접 쓴 레코드로 범위를 좁혀
      읽습니다; ALBA/ALEA 버그 수정·개선 errata는 수집 시점에 버리고, 취약점을 담는 것은
      ALSA뿐입니다
- [x] Amazon Linux 2/2023을 자기 updateinfo 저장소에서 (D73) — Red Hat 이후 첫 non-OSV
      advisory provider; Medium/대소문자 표기 차이를 측정해 매핑; extras는 못 가져왔다고
      공개
- [x] Oracle Linux 5-10을 ELSA OVAL에서 (D74) — 첫 OVAL criteria-tree 파서; UEK의
      definition을 가로지르는 모호성은 버려서 셈; v2뿐인 definition은 NVD 조인으로 떨어짐;
      ksplice/FIPS 계보는 D79부터 필터링됨
- [x] Fedora 현재 릴리스를 Bodhi에서 (D75) — 산문에서 뽑아내지 못한 CVE는 세어서 표시(상한
      81.7%), EOL 동결을 공개, unspecified 심각도는 Unknown으로 남음; 빌드 가능한 RPM 계열이
      닫힘
- [x] ndb rpmdb 백엔드(D76) — openSUSE와 SLES 자신만의 패키지 데이터베이스 컨테이너 포맷으로,
      BerkeleyDB와 SQLite(D44)에 이은 세 번째; 카탈로징만 하며 SUSE advisory 피드는 아직 없음,
      실제 SLES/BCI 이미지로 검증(패키지 138개, skip 0건)
- [x] SLES와 openSUSE Leap을 SUSE CSAF VEX에서 (D77) — advisory 40,221건, RHEL 이후 처음
      나온 fix 상태, 바이트 단위 키 일치를 고정; RPM 계열이 닫힘
- [x] AL2 extras topic을 열거해 가져옴 (D78) — advisory 1,414건으로 AL2가 발행한 전체의
      29.4%(docker, ecs, livepatch, firefox); topic 0개짜리 카탈로그는 모양 변화로 보고
      거부; AL2023 NVIDIA/livepatch는 여전히 공개 상태로 남음
- [x] Ksplice/FIPS 계보 필터 (D79) — 계보 fixed 버전 12,174건을 수집 시점에 떨어뜨리고,
      설치된 계보 패키지는 평가되지 않음으로 보고; UEK 모호성 가드가 버리던 것의 24.4%를
      필터가 되찾음, openssl은 전부
- [x] MODULARITYLABEL 매칭 (D80) — module stream이 끝에서 끝까지 일급 대접을 받음: Red
      Hat module 항목 487,796건을 스트림과 함께 보존, 스트림별 wont-fix, 꼬리를 자른
      비교로 스트림 동등성 매칭; ubi8/nodejs-18은 셋 중 설치된 스트림에만 정확히 매칭됨
- [x] Oracle module stream (D81) — gate가 걸린 fix 17,930건을 Oracle 철자 stream 87개에
      걸쳐 저장, 모호성이 예측 그대로 32,621건→22,939건으로 떨어짐; gate 없는 module EVR
      150개는 계속 시끄러움
- [x] Rocky/Alma module stream을 summary 산문에서 (D82) — 항목 21,540건이 하나-토큰
      규칙 아래 stream을 얻음; 풀리지 않는 레코드 15+96건은 stream 없이 계속 시끄러움;
      MODULARITYLABEL 삼부작이 닫힘
- [x] SBOM의 rpm과 deb purl (D83) — 이미지 경로가 쓰는 것과 같은 Distro.Ecosystem()으로
      키를 잡고, epoch는 자신의 qualifier에서 복원; rockylinux:9는 SBOM과 이미지가
      finding 169건으로 일치하고, 최신 syft SBOM은 더 이상
      --fail-on-incomplete=target에 걸리지 않음
- [x] SPDX 2.2/2.3 JSON (D84) — 공유 purl core가 syft와 Red Hat 벤더 SBOM을 똑같이
      읽음(repository_id, rpmmod, arch=src); rocky9는 SPDX와 CycloneDX가 동일하게
      스캔되고, Red Hat 자신의 ubi9-micro SBOM은 20/20으로 키가 잡힘
- [x] Ubuntu fix state를 Canonical의 CVE tracker에서 (D85) — OSV 변환 시점에 D52
      이음매에 찍음; ubuntu:22.04에서 grype와 정확히 일치(같은 wont-fix 쌍 15개), 그리고
      빌드의 첫 도구 의존성(git)은 조용하지 않고 시끄럽게 실패함
- [x] EPSS와 KEV (D86) — 밴드 순서가 볼 수 없는 typed rating 필드, seed에서 제외되고
      매일 다시 fetch됨, --fail-on-kev와 --fail-on-epss; log4j-core는
      2 known-exploited를 그려내고 Log4Shell이 두 게이트 다 건드림
- [x] 배포판 EOL을 endoflife.date에서 (D87) — Meta에 실리고 제품별 phase 라벨을 달며,
      시계에 대고 스캔 시점에 유도, --fail-on-eol; debian:11은 LTS 조건이 붙은 줄을
      그려내고 grype 대비 마지막 보강 격차가 닫힘
- [x] Wolfi와 Chainguard (D88) — Chainguard fetch 한 번이 무-릴리스 키 둘 다를 커버,
      CGA는 related로 조인, usr/lib apk 경로 probe가 하드 exit 2를 wolfi-base의
      15/15 evaluated로 바꿈
- [x] rating 쓰기를 배치로 묶고 tracker 스풀을 캐시 (D89) — EPSS가 11분에서 2.2초로
      (10,000레코드 청크당 fsync 한 번), seed 복사도 함께 빨라짐, 그리고 야간 작업이
      193MB를 다시 clone하지 않게 됨
- [x] CSAF ID 충돌 (D90) — 두 벤더 모두 맨 CVE를 ID로 저장했고 by-id는
      last-writer-wins; 13-타깃 grype 차등이 ubi9 finding의 91%가 조용히 사라진 것을
      잡음; CVE를 alias로 둔 접두사 ID가 38→415로 복원하고, 차등 장부가 기록됨
- [x] SLES LTSS를 mainline-wins 동점 처리로 접음 (D91) — post-EOL fix가 같은 키
      아래서 드러남(bci-base finding 121→286건, curl이 진짜 FIXED IN을 보여줌),
      가려졌던 쌍둥이 385,621건을 버려서 셈
- [x] MinimOS와 Echo (D92) — D88 템플릿이 그대로 통함(upstream을 통한 CVE, 조인
      변경 없음); Echo는 deb comparer, 커스텀 접미사 둘, 그리고 우연히 안전한 게
      아닌 "1" not-affected sentinel을 가져옴; reg.mini.dev/nginx는 15/15로 스캔됨
- [x] 차등이 스스로 돎 (D93) — 매주, digest로 고정된 타깃 13개를 발행된 아티팩트에
      대고, 커밋된 floor로 판정(`cmd/grypediff`, stdlib만 사용); ratings 컬럼을
      읽어서 죽어 있던 동의 둘을 되살림(alma 0→106, oracle 0→37)
- [x] Azure Linux와 CBL-Mariner (D94) — OSV 계열 하나, os-release ID 둘, 기존 rpm
      comparer; scancmd의 계열 맵은 D43 이후로 두 ID를 테스트 없이 담고 있었음; 오래된
      digest 고정 이미지 둘이 주간 차등에 합류(agree 132/106)
- [x] Alpaquita와 BellSoft Hardened Containers (D95) — fetch 한 번이 두 계열 모두를
      커버하고, apk `p:` provides 다리가 설치된 어떤 패키지도 담지 않는 Liberica
      JDK 이름에 닿음(코퍼스의 10.74%); 그 과정에서 세 번째 apk db 경로(`var/lib`)
- [x] Photon OS (D96) — 새 flat-JSON provider이고 D90의 충돌을 구조적으로 처음부터
      피함(major 셋을 가로질러 CVE당 advisory 하나), Fixed-wins와 BDSA-drop 정책을
      측정하고 셈; 첫 차등이 완벽한 동등성(22/22, 7/7)
- [x] Arch Linux (D97) — 릴리스 없는 `Arch:rolling` 키, `%BASE%`를 D8의 source로
      쓰는 새 pacman cataloger, 그리고 rpm에 절대 alias되지 못하도록 테스트가
      막는 `Pacman{}` comparer(측정된 tensorflow `2.4.0rc4` 미탐)
- [x] Hummingbird (D98) — Red Hat의 강화 라인이고, assay가 이미 받아오는 CSAF
      피드에서 추출함: CPE 범위, purl로 읽음(stream label이 갈라짐), 맨 rolling
      키; 첫날 차등이 grype 전용 튜플 전부를 grype 자신의 낡은 스냅샷으로 추적함
- [x] Bitnami (D99) — 남의 배포판 위에 올라탄 애플리케이션 레이어: purl-type
      라우팅, 리비전을 벗겨내는 SemVer wrapper, 그리고 D84의 SPDX 리더를
      재사용하는 마커 cataloger; 첫날 차등 497/497에 agree 485, 이중 인벤토리를
      증명함
- [x] `requirements.txt` (D38) — 정확히 한 버전을 지목하는 줄만 패키지가 되고, 나머지는 세고
      이름을 밝힙니다. `*`를 `0`으로 바꾸고 `>=`의 최댓값을 취하는 syft가 아니라 pip-audit를
      따릅니다. 실측: 일곱 줄짜리 파일에서 없던 finding 23건

**④ 판정과 출력** ✅ — 종료 코드 1이 처음으로 도달 가능해지는 지점입니다.

- [x] `--fail-on` 심각도 게이팅, `--fail-on-unknown`과 `--fail-on-incomplete`
- [x] CVSS v3.1과 v4.0 채점, 실제 데이터베이스의 모든 벡터로 검증
- [x] 스키마 버전과 골든 파일 테스트를 갖춘 JSON 출력
- [x] explain 모드 — 특정 finding의 매칭 근거 출력
- [x] 출처별 평가 — finding이 모든 데이터베이스의 평가를 유지하고, 게이트는 그중 가장 높은
      것을 취함 (D25)
- [x] 두 번째 평가 출처로서의 NVD, CVE로 조인 (D27)
- [x] SARIF 출력(D55) — `--output sarif`. 평가하지 못한 패키지는 note 수준 결과로도, 도구
      알림으로도 나갑니다. GitHub code scanning이 스펙의 `invocations[]` 채널을 무시하고,
      부분 스캔이 온전한 것으로 읽힐 수는 없기 때문입니다

**⑦ NVD 심각도** ✅ — assay가 OSV로 이미 매칭한 finding에 NIST가 그 CVE를 몇 점으로 보는지 붙입니다.

2026-08-03 측정: 점수 낼 벡터가 없는 권고 8,029건 중 60건 표본에서 NVD가 93%에 점수를 매기고
**48%를 high 이상**으로 평가했습니다. 조인 키는 CPE가 아니라 CVE입니다. NVD는 매치 데이터를
`vendor:product`로 키잡는데 어떤 purl로도 유도되지 않고, 학습된 사전은 Alpine 85%인 반면 Go는
11%입니다 — 8,029건 중 4,125건이 Go인데도요. 무평가 권고 1,008건은 CVE가 아예 없어 어떤 설계로도
unknown으로 남습니다 (D27).

실제 피드로 검증했습니다. assay 자기 바이너리 스캔, 전후 비교:

| | 이전 | 이후 |
|---|---|---|
| 무평가 | 3건 중 3건 | **3건 중 1건** |
| `--fail-on high` | 0 | **1** |

```
stdlib                          high     GO-2026-4970 unknown + NVD CVE-2026-39822 high (7.8)
stdlib                          medium   GO-2026-5856 unknown + NVD CVE-2026-42505 medium (5.3)
github.com/klauspost/compress   unknown  GO-2026-5841 - CVE가 없어 어떤 조인도 닿지 않음
```

세 번째 행이 1,008건의 축소판입니다. CVE가 없어 아무것도 조인되지 않고, 추측하는 대신 `unknown`으로
남습니다. 밴드는 NVD가 정하지만, 권고와 매칭된 범위와 수정 버전은 여전히 assay가 비교한 레코드에서
옵니다.

- [x] NVD provider — 2.0 API 벌크 동기화, API 키 불필요
- [x] CVE로 조인한 rating, 판정은 최고 밴드 (D25의 메커니즘)
- [x] 옵트인(`NVD_ENABLE`)과 범위 제한(`NVD_SINCE_DAYS`), 그리고 `db status`가 그 범위를 출력

옵트인인 이유는 전체 패스가 약 7시간이기 때문입니다 — 추정이 아니라 측정값입니다. NVD가 2,000건
페이지 하나를 114~136초에 걸쳐 생성하며, 압축도 더 작은 페이지도 총 시간을 바꾸지 못합니다. 기본
활성 상태로 두었다면 흔한 NIST 장애가 데이터베이스를 아예 빌드하지 못하게 만들기도 했습니다.

`NVD_SINCE_DAYS`는 **한 번의 빌드** 범위를 제한할 뿐, 그 자체로 매일의 델타는 아닙니다.
`assay db build`는 seed가 없으면 빈 상태에서 다시 빌드하므로, seed 없이 범위를 제한한 실행의
창은 그 데이터베이스의 전체 NVD 커버리지입니다. `db status`는 그것을 `COVERED` 열로 출력해서,
일부만 담긴 데이터베이스가 완전한 것처럼 보이지 않게 합니다. 진짜 델타는 빌더가 빈 상태 대신
기존 데이터베이스 위에 쌓아야 하고, 그것이 아래 슬라이스 ⑧의 `db build --seed <ref>`입니다.

**⑧ 배포되는 데이터베이스** ✅ — 빌더가 느린 동기화를 돌고, 나머지는 결과를 받습니다.
재검토 조건이 "CI 재빌드 시간이 병목이 될 때"였던 보류 결정이고, 위 측정이 그것을 발동시켰습니다.
grype와 trivy 모두 이렇게 동작합니다.

- [x] 데이터베이스를 중앙에서 빌드하고 OCI 아티팩트로 배포(`assay db push`, D28)
- [x] `assay db update`가 재빌드 대신 배포된 아티팩트를 받아옴
- [x] 이전 아티팩트 위에 매일 델타를 쌓기(`assay db build --seed <ref>`), 이 덕분에 예약 배포가
      위의 7시간짜리 전체 NVD 패스에 맞서 GitHub Actions의 6시간 잡 상한 안에 들어감. seed는
      rating은 가져오지만 advisory는 매번 소스에서 다시 빌드하므로, 업스트림이 철회하는
      advisory는 여전히 제거됨

**⑤ KISA 보강** ✅ — 매칭된 finding에 CVE로 한국어 제목·설명·조치 정보를 결합합니다.

첫 조사는 이것이 성립하지 않는다고 했습니다. 틀린 게시판을 쟀습니다 — KNVD 자체 공개(173건, 국내
상용 소프트웨어)를 봤고, 국내 기관에 실제로 쓰는 소프트웨어의 CVE를 패치하라고 알리는 **보안공지**를
보지 않았습니다.

공지 2,039건, 고유 CVE **17,003개**의 수집된 코퍼스로 측정한 결과, **413건(2.4%)**이 assay가 이미
가지고 있는 권고입니다 — Alpine 279, Go 56, npm 56, PyPI 37. KISA 코퍼스는 assay가 스캔하지 않는
데스크톱·엔터프라이즈 소프트웨어(MS, Adobe, Cisco)에 몰려 있고, 겹치는 것은 서버 쪽 롱테일입니다 —
OpenSSL, Apache, Exim, Mozilla. Alpine 권고 약 4,405건 대비로는 finding 16건 중 1건 정도가 한국어
제목과 조치 정보를 얻습니다.

미해결로 기록됐던 것이 둘 있었습니다 — TLS 검증, 그리고 의존성 없이 HTML에서 영향/해결 표를
파싱하는 문제입니다. 2026-08-05, 그것에 대한 문서가 아니라 실제 서비스로 측정한 결과 둘 다
사실이 아니었습니다. `knvd.krcert.or.kr`은 엄격하게 검증되고(`Verify return code: 0 (ok)`,
DigiCert 발급 인증서), 목록 응답은 이미 HTML과 나란히 순수 텍스트인 `content_text`를 담고 있어
파서가 아예 필요 없습니다. 참조 크롤러가 HTML 표를 파싱하는 것은 영향/해결 *버전 규칙*을 만들기
위해서일 뿐이고, D3은 이미 보강에는 그것이 필요 없다고 정해 두었습니다.

실제로 남아 있던 것은 라이선스였고, 그것을 정한 것이 D29입니다. KISA 사이트는 공공누리 표시 없이
모든 권리를 보유하고 있으며, 이는 만든 데이터베이스를 재배포하는 것을 제한하지 그것으로 스캔하는
것을 제한하지 않습니다. 그래서 `db build`에 `KISA_ENABLE=1`을 주면 KISA의 한국어 산문을 받아와
로컬에 저장하고, `db push`는 배포 전에 그것을 벗겨냅니다 — `db update`는 그래서 그것을 결코
전달하지 않고, 원하는 사람은 직접 `db build`를 돌립니다. 라이선스 문제가 풀리면 되돌리는 것은 그
벗겨내기를 지우는 일입니다. KISA 자체 count 엔드포인트가 실제로는 동작하지 않는다는 것과 자신의
장애를 어떻게 보고하는지를 포함한 자세한 내용은 로드맵에 있습니다.

- [x] KNVD provider와 CVE 기반 보강 조인

**첫 전체 코퍼스 빌드, 2026-08-05.** 슬라이스 ⑦·⑧·⑤를 창 제한 없이 처음으로 함께 돌렸습니다.
**6시간 31분**, advisory 32,272건, NVD는 등급이 붙은 CVE **354,067**건으로 피드 전체, KISA는 공지
2,971건에서 뽑은 보강 **18,523**건. `ghcr.io/kun9497/assay-db:v7`로 배포했습니다. 그 뒤 배포된
레이어를 다시 받아 바이트로 읽었습니다. 로컬 빌드는 한글 시퀀스 **1,719,126**개를 담고 있고 배포된
아티팩트는 **0**입니다 — D29를 테스트가 아니라 사용자가 내려받는 파일에 대고 확인했습니다.

**⑪ 데비안 패키지** ✅ — `debian:12`가 Alpine처럼 끝에서 끝까지 스캔됩니다.

성립 여부를 가른 질문은 Debian에 Red Hat의 backport 문제가 있는가였고, 측정의 답은 아니오입니다.
Debian은 backport를 버전에 **적습니다**(`7.74.0-1.3+deb11u10`). (CVE, 소스, 릴리스) 삼중항
169,282개를 Debian 자체 보안 트래커와 대조해 불일치가 0입니다.

- [x] dpkg 버전 comparer, CI에서 진짜 `dpkg --compare-versions`와 대조 (D40)
- [x] `/var/lib/dpkg/status`를 RFC822가 아니라 deb822로 읽고, 설치 여부는 `Status`의 셋째
      낱말로 판단 — syft는 `deinstall ok installed`를, trivy는 `purge ok installed`를 버리는데
      둘 다 파일이 디스크에 있는 패키지입니다
- [x] 비교하는 버전이 advisory에 닿은 이름을 따라감 (D41) — Debian 패키지의 13~15%가 바이너리와
      다른 소스 버전을 갖습니다
- [x] Ubuntu(D53) — 메인라인 릴리스로 키를 잡습니다. `Ubuntu:22.04:LTS` 또는 `Ubuntu:25.10`.
      Pro, FIPS, Realtime 계보는 **같은 릴리스**를 가리키므로 수집 시점에 버리고, 설치된
      버전이 `+esmN`이나 `+FipsN`을 달고 있는 패키지는 메인라인 데이터로 판단하는 대신
      평가 불가로 보고합니다. 측정이 예상을 뒤집었습니다 — 오류는 FIPS 호스트에서의 조용한
      **미탐**이지 오탐이 아닙니다. Canonical이 같은 베이스 버전에 `+FipsN`을 붙이고
      dpkg가 그것을 위로 정렬하기 때문입니다
- [x] distroless 이미지는 데이터베이스를 `var/lib/dpkg/status.d` 디렉터리에 둡니다(D54).
      `Image.FilesUnder`가 이름 지정 경로와 같은 레이어 규칙으로 열거합니다 — 최신 레이어가 이기고,
      whiteout은 아래 레이어를 가리되 자기 레이어는 가리지 않으며, opaque 표식은 디렉터리를
      교체합니다. 그 아래의 심볼링크는 따라가지 않고 세서 불완전 카운트에 더합니다

**⑫ RHEL 계열 인벤토리** ✅ — `ubi9`, `rocky:9`, `almalinux:9`, `fedora`,
`amazonlinux:2023`를 읽지만, **판정은 따라오지 않습니다**. RHEL 이미지의 패키지는 NEVRA와
함께 나열되고 전부 평가되지 않음으로 보고되므로 스캔은 exit 2입니다. **인벤토리는 끝났고,
매칭은 의도적으로 하지 않습니다.**

기록해 둔 반론 — Red Hat이 버전에 밝히지 않고 fix를 백포트하므로 비교가 오탐을 낸다는 것 —
은 **틀린 것으로 드러났고**, 그 정정은 `docs/deferred-decisions.md`에 있습니다. Red Hat의
OSV export에 있는 fixed 이벤트 588,150건 전부가 epoch와 release를 달고, 95.8%가
`.elN`을 달며, 실제 `ubi9` 이미지에 대고 보면 패치된 패키지 전부가 fixed로 읽힙니다.
매칭을 막는 것은 다른 문제입니다: 그 피드는 **errata 전용**이라 "affected, will not fix"를
표현할 수 없습니다 — CVE 39,372개가 Red Hat의 VEX 피드에만 존재하고, 그중 19,341개가
2023년 이후입니다. 그 피드만으로 매칭하면 전부 clean으로 보고하게 됩니다.

- [x] `rpmdb.sqlite`를 읽는 순수 Go SQLite 리더, overflow 체인 포함 — 새 의존성 없음(D44).
      스캐너는 열거만 하므로 해시 인덱스도 SQL 계층도 사표입니다. `modernc.org/sqlite`는 모듈
      4개와 3.8 MB를 치르고 정작 가장 쓰기 쉬운 백엔드 하나를 사 옵니다
- [x] RPM 헤더 파서, 그리고 D8의 소스 이름 간접 참조로 쓰는 `SOURCERPM`
- [x] 비어있지 않은 write-ahead log와 손상된 페이지는 하드 에러이고, 가드는 **sibling 파일**을
      읽습니다(D45) — rpm은 항상 WAL 모드라 헤더의 버전 바이트에 건 가드는 발화할 수 없습니다
- [x] `/var/lib/rpm`과 `/usr/lib/sysimage/rpm`을 둘 다 살핍니다. 앞의 것은 RHEL 10, Fedora,
      CentOS Stream 10에서 심볼릭 링크이고, RPM 배포판인데 데이터베이스를 못 찾으면 빈 인벤토리가
      아니라 하드 에러입니다(D43)
- [x] `rpmvercmp` comparer, CI에서 실제 `rpm`과 대조(D46). 작성했지만 **등록하지 않았습니다**.
      provider가 없는 상태에서 comparer가 해석되면 빈 조회가 clean으로 보고됩니다
- [x] Red Hat advisory provider(D47–D49). fix 없는 영향 상태를 표현할 수 있는 유일하게 완전한
      출처가 CSAF VEX였고, CPE에서 온 903개 생태계 키는 메인라인만 수집하는 것으로 답했습니다 —
      지원 채널은 파일시스템에 표현이 없으므로 EUS/AUS/E4S 호스트는 메인라인 errata에 맞춰지고
      스캔이 그것을 stderr에 밝힙니다
- [x] RHEL 8과 Amazon Linux 2를 위한 BerkeleyDB(`Packages`)(D44) — 약 300줄, 여전히 의존성
      없음, 그리고 ubi8의 실제 11 MB 데이터베이스로 검증했습니다. 183 패키지, 183건 전부 syft와
      공유, 소스 이름 불일치 0건. 빅엔디언 데이터베이스도 읽습니다. BerkeleyDB가 호스트 순서로 쓰고
      s390x가 지원 플랫폼이기 때문입니다
- [x] openSUSE와 SLES를 위한 ndb(`Packages.db`)(D76) — 카탈로징만 하며 여전히 SUSE
      advisory 출처는 없습니다; 실제 SLES/BCI `Packages.db`로 검증했습니다: 패키지 138개,
      skip 0건, 소스 이름을 정확히 벗겨냈습니다. 그 이미지들은 이제 데이터베이스조차 열지
      못해 exit 2 하는 대신 끝까지 스캔되어 평가되지 않음으로 보고됩니다
- [ ] write-ahead log를 거절하는 대신 재생하기

**⑬ Red Hat advisory provider** ✅ — `assay db build`가 Red Hat의 CSAF VEX 피드를 넣습니다. RHEL
패키지가 취약하고 **수정되지 않을 것**이라고 말할 수 있는 유일한 출처입니다. D51 이후 기본 켜짐이고
**발행되는 아티팩트가 실으므로** `assay db update`로도 받습니다. 다운로드가 20.9 MB에서 28.7 MB가
됩니다.

실제 2026-08-05 아카이브를 89초에 끝에서 끝까지 스트리밍한 측정:

```
67,261 documents -> 28,907 advisories, 1,918,779 affected entries
(1,278,384 with no fix available); skipped 431,985 module builds,
3,234,355 non-mainline products, 216,790 container images, 9,430
whole-product entries naming no package, 0 unreadable products,
0 unreadable documents
```

스키마 변경 없이 D1이 성립합니다. 이것이 말할 값어치가 있는 결과입니다. CSAF의 "fix 없는 affected"는
`introduced` 이벤트만 있고 `fixed`가 없는 OSV range이고, 스토어는 이미 이해하고 있었습니다.

- [x] 스트리밍 CSAF VEX 리더 — 압축 262 MB, 압축 해제 17.1 GB, 최대 단일 문서 94 MB, 디스크에
      아무것도 쓰지 않음(D49)
- [x] **새 의존성 없음.** go-containerregistry가 zstd 레이어 때문에 끌어와서
      `klauspost/compress/zstd`가 이미 링크되어 있었습니다. `go mod tidy`가 옮긴 것은 한 줄이고,
      `go.sum`은 바이트 단위로 동일하며 모듈 수는 52로 그대로입니다
- [x] 생태계 키는 메인라인 major(D47) — CPE 모양이 462가지이고, 그것들이 담은 지원 채널은
      파일시스템에 표현이 없는 구독 속성입니다
- [x] fix 없는 affected를 `fixed` 이벤트 없는 range로 저장(D48)
- [x] CI에서 **실제 피드**로 검증하고, 양이 아니라 모양을 단언합니다. CVE-2024-6387은 여전히 fixed
      `openssh` range를, CVE-2005-2541은 fix 없는 `tar` range를 내야 합니다
- [x] 매칭(D48, D50) — RPM comparer가 등록되고, RPM 패키지가 메인라인 major로 키를 잡으며,
      `--fail-on-unfixable`이 고칠 수 없는 finding을 게이트합니다
- [x] 왜 픽스가 없는지(D52) — Red Hat의 remediation 카테고리가 "안 고칠 것"과 "아직 안 고쳐진
      것"을 가르고, `--fail-on-unfixable=wont-fix`가 앞쁳것에만 걸립니다. 픽스 없는 메인라인
      튜플 1,282,093건 전부가 이유를 실어 있어서 일부가 아니라 전체에 적용됩니다.
      ubi8:8.9에서 505건 중 59건, ubi9:9.3에서 416건 중 11건
- [x] EUS/AUS/E4S 호스트가 메인라인 errata에 맞춰지고, 스캔이 그것을 stderr에 밝힙니다

```
PACKAGE             VERSION          ECOSYSTEM  ADVISORY       FIXED IN
audit-libs (audit)  3.1.5-8.el9      Red Hat:9  CVE-2024-0003  3.1.5-99.el9
openssl-libs        1:3.5.5-6.el9_8  Red Hat:9  CVE-2024-0001  1:3.5.5-8.el9_8
vim-minimal         2:8.2.2637-22    Red Hat:9  CVE-2024-0002  won't fix
python3-libs        3.9.21-2.el9     Red Hat:9  CVE-2024-0004  no fix yet
zlib                1.2.11-40.el9    Red Hat:9  CVE-2005-2541  none
none = no source records a version that fixes this; mitigate or remove the package
```

`none`과 `-`는 다른 사실이고 이 열은 둘을 구별합니다. `none`은 어느 출처도 올라갈 버전을 대지
않는다는 뜻이고, `-`는 이 finding의 심각도를 정한 레코드에는 없지만 다른 출처에는 있다는 뜻입니다.
올릴 수 있는 패키지를 제거하라고 말하는 것은 아무 말도 안 하는 것보다 나쁩니다.

`Red Hat:N`으로 가는 것은 `rhel`뿐입니다(D50); Rocky Linux는 `Rocky Linux:N`으로(D71),
AlmaLinux는 `AlmaLinux:N`으로(D72), Amazon Linux 2/2023은 `Amazon Linux:2` /
`Amazon Linux:2023`으로(D73), Oracle Linux 5–10은 `Oracle Linux:<major>`로(D74), Fedora의
현재 릴리스는 `Fedora:<release>`로(D75), SLES 15.x/16.0과 openSUSE Leap은
`SLES:15.SPn` / `SLES:16.0` / `openSUSE Leap:15.6`로(D77) 갑니다 — 각자 자기만의 advisory
피드만 상대하지, Red Hat의 것도 서로의 것도 상대하지 않습니다 — openSUSE Tumbleweed는
경로를 잡는 대신 이름으로 거부합니다. 롤링 릴리스는 키로 잡을 릴리스 축이 없기 때문입니다.
`centos`는 RHEL을 뒤따른 제품과 앞서 가는 제품을 한 ID로 덮습니다 — 여전히 카탈로그되고
평가되지 않음으로 보고되며, Amazon Linux 1, AL2022, 그리고 13개월 EOL을 지난 Fedora
릴리스도 마찬가지입니다. 시끄러운 skip이지 깨끗한 판정이 아닙니다.

Rocky의 판정은 Rocky가 발행한 것에 한해 깨끗하다는 뜻입니다: 그 피드는 errata뿐이고 RHSA보다
얇게 측정되며(regreSSHion 권고가 아예 없습니다), module 빌드로 얻는 fix는 stream까지 매칭하지
않고 세어서 건너뜁니다. AlmaLinux의 판정도 같은 errata뿐이라는 단서를 지니면서, 자기만의
단서도 하나 더 얹습니다: 그 아카이브는 CVSS 벡터를 하나도(0%) 담고 있지 않아서 모든
AlmaLinux 심각도는 점수가 아니라 벤더 자신의 단어(Critical/Important/Moderate/Low)이고, CVE
연결은 `aliases`나 `upstream`이 아니라 `related`를 통해 이루어집니다 — 둘 다 무손실로
저장되고 올바르게 읽히지만(D72), Red Hat이나 Rocky 판정과 비교해 유난히 단어 위주로 보일 때
알아 두면 좋습니다.

이제 Amazon의 판정은 AL2 core에 extras topic 73개 — docker, ecs, 커널 livepatch를
비롯한 나머지 — 를 더해 같은 방식으로 가져오고 매칭한 것을 반영합니다(D78). 대신 공개된
채로 남는 것은 AL2023 쪽입니다: NVIDIA(306건)와 livepatch(286건) advisory가 D78이 닿지
못한 저장소 레이아웃의 AL2023 core 바깥에 살아 있고, `db build`가 그 구멍을 나중에 스캔에서
발견되게 두는 대신 빌드 시점에 찍어 보여줍니다.

Fedora의 판정은 공개된 한계 두 가지를 물려받습니다: Bodhi 업데이트 산문에서 CVE를 뽑아내는
것은 측정된 상한 81.7%에서 멈추고, EOL된 릴리스의 advisory는 스캔을 막는 대신 그 자리에서
얼어붙습니다 — `db build`가 나중에 발견되게 두는 대신 둘 다 빌드 시점에 찍어 보여줍니다.

SUSE에서는 `--fail-on-unfixable`이 동작하지만 `=wont-fix`는 SUSE가 분류해 둔 것만 잡습니다
— fix 없는 항목의 99.96%가 이유를 밝히지 않으며(측정값), 이는 Red Hat과는 정반대입니다.

- [ ] EUS 호스트의 `Red Hat:N` 스캔은 여전히 메인라인 fixed 버전을 인용합니다. 2026-08-11 측정:
      달라지는 155,549개 그룹 중 149,726개(96.3%)에서 오류는 **오탐** 방향 — 시끄러운 쪽 — 이고
      1.3%가 조용한 꼬리로 남습니다. release 접미사로는 닫을 수 없습니다(`.elN_M`은 z-stream을
      뜻하고, 메인라인이 RHEL 9 항목의 92.6%에서 그걸 씁니다). `docs/deferred-decisions.md` 참조

**⑨ comparer가 읽지 못하는 버전** ✅ — 버전이 파싱되지 않는 패키지는 clean이 아니라 skip으로
보고됩니다(D20, D21), 그래서 시끄럽습니다; 그것은 여전히 평가받지 못한 취약점이고, D9는
그것을 miss라고 부릅니다. 2026-08-06 측정, v7 데이터베이스의 모든 범위 경계 기준: semver
경계 29,840개 중 96개, pep440 31,147개 중 45개, apk 53,819개 중 61개 — 패키지 86개에 걸쳐
0.18%. 지배적인 원인은 이색적인 것이 아니라 문법이 요구하는 것보다 구성 요소가 적은 버전입니다
(`lxd`의 `4.0`, `next`의 `13.0`). 실제 스캔이 같은 날 둘을 맞닥뜨렸습니다: `alpine:3.14`가
`libretls 3.3.3p1-r3`를, 그와 함께 CVE-2022-0778을 건너뛰었습니다.

- [x] `affected[].versions`의 읽을 수 없는 항목은 건너뛰고 세지, 치명적이지 않음 (D30) —
      열거 항목 1,309,665개 중 2,411개가 파싱되지 않고, 그중 하나면 읽히는 패키지를 평가
      불가로 보고하기에 충분했습니다
- [x] apk: 문자가 숫자 패치 레벨을 가질 수 있음 (D31) — `libretls 3.3.3p1-r3`,
      `sudo 1.7.4p6-r0`. 출시된 모든 Alpine이 싣는 apk-tools 2.x를 따릅니다. 3.x는 이것들을
      거부하고 `3.3.3p1-r3`와 `-r2`를 EQUAL로 답해 패치되지 않은 호스트를 고쳐진 것으로
      읽습니다. 파싱 안 되는 apk 경계 61 -> 39, 열거 버전 -> 0
- [x] semver: 접미사 없는 짧은 core를 0으로 채움 (D32) — `lxd`의 `4.0`, npm `next`의
      `13.0`. `golang.org/x/mod/semver`가 문서화한 축약형 그대로이고 govulncheck가 이
      경계들에 그것을 씁니다. `4.0-rc1` 같은 접미사 형태는 두 레퍼런스 모두 거부하므로
      에러로 남습니다. 파싱 안 되는 semver 경계 96 -> 40
- [x] 선행 0 core는 거부가 아니라 정규화 (D34) — `19.03.0`이 `19.3.0`과 같고, node-semver의
      loose 모드입니다. 받아들이기와 정규화는 하나의 규칙입니다. `compareNumeric`이 자릿수를
      먼저 보므로 벗기지 않고 받으면 `4.072`가 `4.72`보다 위로 갑니다. 선행 0을 거부하는
      `x/mod`와의 의도적 이탈이며, 대안은 `docker/docker`·`moby/moby`·`docker/cli`가 영구히
      평가 불가로 남는 것입니다. 파싱 안 되는 semver 경계 40 -> 12, 그리고 `assay`가 자기
      바이너리를 평가 못 한 패키지 없이 스캔합니다
- [x] 누구의 데이터가 읽히지 않는지 밝힘 (D35) — 기형인 advisory 경계와 읽히지 않는 설치
      버전이 둘 다 `not evaluated`로 나왔는데, 독자에게 정반대의 뜻입니다. 이제 리포트가
      어느 쪽인지 말합니다
- [x] Alpine의 `.rN`을 `-rN`으로 수집 시점에 수리 (D35) — 11개 경계, 데이터베이스의 apk
      `fixed` 실패 전부. comparer에 가르치지 않았습니다. apk-tools 2.x는 그 오타를 파싱하고
      오타의 원본보다 *위로* 정렬합니다
- [x] 불완전함이 원인을 갖고, `--fail-on-incomplete=target`이 게이트를 호출자가 조치할 수
      있는 것으로 좁힘 (D36) — 기형 advisory 경계 85개가 아니면 넓은 게이트를 영원히
      빨간불로 두고, 꺼진 게이트는 아무것도 지키지 않습니다
- [ ] 경계 하나가 읽히지 않는 range의 부분 평가 — **기각**, D35 참조. Alpine imagemagick이
      `introduced 7.0.0-0`을 `fixed 6.9.6.8-r0` 위에 갖고 있어서, 나쁜 경계를 `0`으로 보면
      창이 넓어지는 게 아니라 뒤집힙니다
- [ ] pep440 관용 — 보류. 후보 규칙 둘을 합쳐도 advisory 경계 2건을 살립니다
- [x] apk는 apk-tools 자신의 738개 비교 벡터 파일로 CI에서 재생하며 검증
- [x] semver가 npm/node-semver 자신의 비교 픽스처를 재생하고, 그 31개 느슨한 입력 형태를 음성
      픽스처로 거부합니다 (D39)
- [x] 두 명세의 순서 사슬을 오프라인으로 검사 — 이웃뿐 아니라 모든 쌍, 전이성과 반대칭까지
      (55쌍 + 136쌍)
- [x] **측정 결과 손으로 쓴 표는 약점이 아니었습니다.** 적합성 코퍼스는 존재하지 않고,
      `x/mod/semver`는 `v` 접두사를 요구해 `1.2.3`과 `1.2.4`를 같다고 정렬하며(실제 경계의
      20.6%), packaging 코퍼스는 `1.9 > 1.10`이라 말하는 comparer를 통과시킵니다

**⑩ 어느 KISA 공지가 이기는가** ✅ — 처음 실제로 써 보면서 발견했습니다. 보강 버킷이
`(CVE, Source)`로 키를 잡으므로 KISA 공지 둘이 지목한 CVE는 나중에 도착한 쪽만 남습니다.
`convert`가 20,314건을 내보냈고 저장소는 18,523건을 지켰으니 **1,791**건이 페이지 순서로
정해졌습니다 — D25가 금지하는 동점 처리입니다. 그리고 저장된 레코드의 70%가 CVE 20개 초과를
주장하는 공지에서 나왔고(하나는 1,046개를 주장합니다), 그래서 실제 스캔에서 만난 보강된 finding은
전부 마이크로소프트 월간 공지를 마이크로소프트와 무관한 취약점에 붙였습니다. 보강은 판정을 바꾸지
않으므로(D3) ⑨ 뒤에 놓았습니다.

- [x] 가장 좁은 공지가 이김, 동수면 공지 URL로 결정 (D33) — 20,315개 중 1,791개가 페이지 도착
      순서로 정해지고 있었고, D25가 금지하는 동점 처리입니다
- [x] 폭은 제거가 아니라 공개 — 선택 이후에도 레코드의 **70%** 가 CVE 20개 초과를 지목한
      공지에서 나옵니다. 대부분의 CVE에게 월간 공지가 유일한 출처이기 때문입니다.
      `--explain`이 그것을 말하고 JSON이 `claims`를 실어 나릅니다
- [x] 요약 추출은 측정 후 그대로 둠 — 라이브 공지 100건 중 65건에 `□ 개요`가 있고 느슨한
      매칭으로는 67건이며, 나머지 33건은 개요 절이 아예 없습니다

**첫 부트스트랩 뒤에 수동 단계가 하나 있습니다.** 아티팩트는 처음 한 번 개인 토큰으로 손수
푸시되는데, 그러면 ghcr 패키지가 계정 소유가 되고 어떤 저장소에도 연결되지 않습니다. 그리고
워크플로의 `GITHUB_TOKEN`은 **자기 저장소에 연결된** 패키지만 건드릴 수 있습니다. 연결이 생기기
전까지 예약된 배포는 권한을 어떻게 선언하든 `DENIED`로 실패합니다. 패키지 페이지에서 한 번
연결하세요 — *Package settings → Manage Actions access → 저장소를 Write로 추가*. 푸시는
`org.opencontainers.image.source`를 실어 나르므로 워크플로가 만든 패키지는 스스로 연결됩니다.
그 이전에 손으로 만든 것은 그렇지 않습니다.

정확성은 매 단계 **grype와의 대조 테스트**로 검증합니다 — D93부터는 매주 일정으로
돕니다(`grype-diff.yml`: digest로 고정된 타깃 13개, 발행된 아티팩트, 퇴보하면 걸리는
커밋된 floor). 데이터 소스가 다르므로 완전한 일치는 기대하지 않지만, **큰 차이가
나면 우리 매처가 틀린 것입니다.** 슬라이스 ①은 대조한 두 SBOM 모두에서
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
