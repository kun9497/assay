# 컨테이너 이미지 안의 애플리케이션 패키지 — 고정 위치 프로브 (D70 revised)

*[English](2026-11-09-image-app-probe-design.md) · 한국어*

상태: **2026-11-09 승인, D160으로 구현**(`ownedBy` 필드는 오늘 어떤 OS 카탈로거도 파일 목록을 읽지
않는다는 것이 드러나 후속 작업으로 미뤘다가 같은 날 D162로 들어감 — `locations[].ownedBy`는 아래
제안한 문자열 하나가 아니라 `{name, version}`; `applicationPackages`는 `partial`; 프로브는 레이어 패스
하나를 공유). 결정 기록: D70을 개정하는 로드맵 D160. `docs/deferred-decisions.md`의 유보 항목 "Application packages inside container images"를
새 정보로 다시 연다: 2026-11-04 QA의 §8 항목 S-1이 이 간극을 서비스의 차단 요인으로 지목했고,
2026-11-09에 scanner-diff 타깃 26개 전부를 측정해 간극이 정확히 어디에 있는지 드러났다.

## 의도

이미지 스캔은 운영체제와 Bitnami 마커를 인벤토리화하고 그 위에 설치된 언어 패키지는 읽지 않는다(D70).
D141이 그것을 stderr와 SARIF에 공개하고, D111의 `inventoryScope.applicationPackages`가 JSON에서
`not-read`라고 말한다. assay를 감싸는 서비스는 오늘 핀된 SBOM 생성기로 이 간극을 닫는다(유보 항목의
"서비스 측 하이브리드", 2026-11-09 결정). 이 문서는 assay 측 절반이다: 간극이 실제로 취하는 두 모양을
읽고, 보고서에 그렇게 말하고, 나머지는 전처럼 공개된 채 둔다.

## 측정한 것 (2026-11-09)

`s1probe`가 scanner-diff 타깃 26개(linux/amd64)의 모든 레이어를 스트리밍하며 고정 위치 프로브가 읽을
것과 놓칠 것을 셌다(증거: QA 폴더 `main-qa-2026-11-04/s1-probe-2026-11-09/`). 같은 날의 주간
차등(실행 42537001178)에는 세 타깃에 grype 전용 애플리케이션 튜플이 있다: ubi8n18 npm 41, bci156
go-module 47, cleanstart-postgres go-module 1 — 총 89건이고 lockfile·jar·Python 타입은 0건.

| 무엇 | 어디서 발견 | 수 |
|---|---|---|
| `usr/lib/node_modules`, `usr/local/lib/node_modules`, `opt/app-root/src/node_modules` 아래 설치된 `package.json` | ubi8n18에만: 236(npm 자신의 트리 202, nodemon 33, corepack 1; 중첩 233; distinct 이름 199, 두 경로 이상인 이름 24, 그중 두 버전 이상 22) | 236 |
| 그 밖의 `node_modules` 아래 설치된 `package.json` | 26개 어디에도 없음 | 0 |
| `usr/bin`, `usr/local/bin`, `bin`, `sbin`, `usr/sbin`, `usr/libexec`, `usr/local/sbin` 바로 아래의 Go 바이너리(Go 빌드 정보가 있는 ELF) | bci156 `usr/bin/container-suseconnect`; cleanstart-postgres `usr/bin/gosu`; archlinux `usr/bin/captree` | 3 |
| `opt/`, `app/`, `usr/lib*`, `usr/share/`, `usr/local/` 아래의 Go 바이너리 | 없음 | 0 |
| `*.dist-info` | ubi8n18 2, ubi9 5, ubi10 9, alma9 2, ol9 2, archlinux 1 — OS 소유로 추론(grype의 소유권 중복 규칙이 떨어뜨림; grype 전용 python 튜플 0) | 21 |
| `*.egg-info` | ubi8n18 14, ubi9 9, ubi10 6, rocky9 1, alma9 2, ol9 2, az2023 2, amazonlinux2 3 — 같은 추론 | 39 |
| jar | liberica21 1, bitnami-legacy-pg 3(grype 전용 java 튜플 0) | 4 |
| 열세 형식의 lockfile | 없음 | 0 |

측정된 모든 튜플은 두 모양으로 설명된다: **전역 npm 트리**와 **표준 bin 디렉터리의 Go 바이너리**.
ubi8n18의 npm 튜플 41건 중 3건은 assay가 소유 RPM(`npm`, `nodejs-nodemon`) 이름으로 이미 보고하는
CVE다: 그 트리는 RPM 소유다.

## 한 문단 결정

이미지 스캔에 **고정 위치 프로브** 둘이 생긴다. OS 인벤토리 뒤에 이미지가 이미 가진 프리미티브로 돈다:
(1) 위 세 node_modules 루트 아래의 모든 설치된 `package.json`이 이름·버전·설치 경로를 가진 `npm`
패키지가 된다; (2) 위 일곱 bin 디렉터리 바로 아래의, 처음 4바이트가 ELF이고 Go 빌드 정보를 가진 실행
가능 일반 파일이 `file:` 타깃 경로가 이미 도출하는 `Go` 패키지들(main 모듈, 의존성, stdlib)이 된다.
이미지 안의 다른 것은 아무것도 읽지 않는다 — Python `dist-info`, jar, 그 밖의 `node_modules`, 그 밖의
Go 바이너리는 `not-read`로 남고 보고서가 어느 것인지 말한다. 프로브는 새 한도 없이 D112의 기존 예산
아래에서 돈다. JSON 보고서는 ecosystem별로 무엇을 읽고 읽지 않았는지 말하고, 주간 차등은 npm과
go-module을 "이미지 스캔이 읽지 않는 타입"으로 취급하기를 멈춘다.

## 왜 이 두 모양이고 전체 트리 walk가 아닌가

전체 트리에 대해서는 D70의 이유가 여전히 성립한다: 아무도 이름 대지 않은 경로의 `node_modules`나 jar는
Source 인터페이스가 노출하지 않는 walk가 필요하고, `/` 아래 모든 파일을 ELF 매직으로 읽는 것은 큰
이미지에서 D112의 스캔당 2 GiB 예산과 충돌한다(예산은 "잘림이 아니라 오류"라 애플리케이션 패스 때문에
OS 판정을 잃는다 — 역전). 측정은 전체 트리가 간극이 있는 곳이 아니라고 말한다: 이미지 26개, 고정 위치
밖의 애플리케이션 파일 0개. 이름 댄 위치의 프로브는 새 프리미티브가 필요 없고(`FilesMatching`은 이미
이름 댄 디렉터리 아래 어느 깊이든 매칭하고 바이트를 레이어와 함께 돌려준다 — 유보 항목이 기록한
groundwork) 그 위치의 크기로 자기 비용을 한정한다. Python과 Java는 측정이 튜플 0건을 찾았고, 발견된
dist-info 파일이 OS 소유라 밖에 둔다: 패키지 관리자의 파일 소유권 없이 읽으면 RPM으로 설치된 모든
Python 모듈을 두 번 보고하게 된다. python이나 java 타입에서 `maxGrypeOnlyApp` ceiling이 트립하는 날,
그것이 같은 프리미티브 위의 다음 증분이다.

## 규칙

**npm 프로브.**
- 루트는 D112의 한도처럼 코드에 고정: `usr/lib/node_modules`, `usr/local/lib/node_modules`,
  `opt/app-root/src/node_modules`. 없는 루트는 아무것도 찾지 못하는 `FilesMatching` 패스 하나의 비용.
- *설치된* `package.json`은 부모 디렉터리의 부모가 `node_modules`이거나, 부모가 `node_modules`인
  `@<scope>`인 것(syft의 규칙). 패키지 안의 `esm/package.json`, `*-package.json`, 테스트 픽스처는
  패키지가 아니다.
- 이름과 버전은 파일에서 온다. `name`이나 `version`이 없는 파일은 세어지는 skip이고(D36의 원인:
  `unreadable package.json`), 빈 필드를 가진 패키지가 결코 아니다.
- 중첩 트리도 그 자체로 패키지다: `node_modules/npm/node_modules/minimatch`는 그 버전의
  `minimatch`이고 그 경로에 있다. 한 이름의 두 버전 사본은 두 패키지다(ubi8n18에 그런 이름 24개);
  finding이 각각의 위치를 실어 어느 사본이 영향받는지 보인다.
- ecosystem 키 `npm`; purl `pkg:npm/<name>@<version>`(scoped 이름은 npm lockfile 카탈로거가 이미
  철자하는 대로 URL 이스케이프), 그래서 `--vex`가 닿는다(D121).
- **소유권.** OS 인벤토리에 그 트리가 놓인 루트를 파일 목록에 가진 패키지가 있으면 — rpmdb와 dpkg
  카탈로거는 D153/D8을 위해 이미 파일 목록을 읽는다 — npm 패키지의 위치가 소유자를 기록한다. 추가형
  `locations[].ownedBy` 필드(`"npm-1:8.19.4-1.module+el8.9.0+..."`)로 제안한다. 그러면 서비스가 "이것은
  Red Hat이 번들한 npm이고 조치할 것은 RPM 자신의 권고"라고 보여 주고 RPM finding과 CVE로 중복 제거할 수
  있다. **사용자 결정 필요:** `ownedBy`를 이번 증분에 넣을지(스키마 bump, 추가형) 미룰지.

**Go 바이너리 프로브.**
- 디렉터리 고정: `usr/bin`, `usr/local/bin`, `bin`, `sbin`, `usr/sbin`, `usr/libexec`,
  `usr/local/sbin` — 직접 자식만, 재귀 없음.
- 후보: 실행 비트가 있고 크기 ≥ 1 KiB인 일반 파일. 처음 4바이트를 레이어 스트림에서 읽고, ELF가 아닌
  파일은 더 읽지 않고 건너뛴다(`collect`의 엔트리 읽기에 스니핑 훅 하나 — 유일한 프리미티브 변경, 그래서
  `/usr/bin/bash`는 전체 크기가 아니라 4바이트의 비용). ELF 파일은 D112의 파일당·스캔당 한도 아래에서
  통째로 읽어 `debug/buildinfo.Read`에 넘긴다. Go가 아닌 ELF는 조용히 건너뛴다(패키지가 아니다).
- Go 바이너리는 오늘 `assay scan file:<binary>`가 내는 것을 낸다: main 모듈, 각 의존성 모듈의 버전,
  툴체인 버전의 Go 표준 라이브러리, 키 `Go`, 위치는 바이너리 경로. `gobinary.Parse`에 바이트 진입점이
  생기고 `file:` 경로는 자기 것을 유지한다.
- `(devel)` main 버전(측정된 세 바이너리 중 둘; archlinux의 `captree`는 main 모듈이 아예 없다)은 프로브에서
  **컴포넌트가 아니다** — 브랜치의 차등 dispatch가 세 타깃에서 Go 바이너리당 `targetIncomplete` 하나씩
  더하는 것을 보여 준 뒤 정한 규칙: 바이너리는 그것을 설치한 OS 패키지로 식별되고, 프로브가 기여하는 것은
  의존성과 stdlib이다. `file:` 경로는 계속 센다(D36).

**예산.** 새 한도 없음. 프로브는 다른 모든 이미지 읽기처럼 `MaxFileBytes`와 `MaxScanBytes` 아래에서
읽고, 어느 쪽이든 넘으면 D112대로 exit 2다. 측정: 가장 큰 Go 바이너리는 7 MB, ubi8n18 트리 전체는 작은
파일 236개라 예산 근처에도 가지 않는다. `/usr/bin`을 2 GiB의 Go 바이너리로 채운 적대적 이미지는 스캔을
실패시키는데, 그것이 다른 모든 적대적 모양에 대한 D112의 규칙이다.

**공개.** `inventoryScope.applicationPackages`는 세 값(D111)을 유지하되 추가형 형제
`inventoryScope.applicationScope[]`를 얻는다. 이미지 경로가 아는 애플리케이션 ecosystem마다 레코드
하나: `{ "ecosystem": "npm", "state": "read", "roots": [...] }`, `{ "ecosystem": "Go", "state":
"read", "roots": [...] }`, `{ "ecosystem": "PyPI", "state": "not-read" }`, `{ "ecosystem":
"Maven", "state": "not-read" }`. **사용자 결정 필요:** 프로브가 돈 뒤 `applicationPackages` 자체가 뭐라고
말할지 — `read`(npm/Go에는 참, Python/Java에는 거짓), `not-read`(이제 거짓), 또는 네 번째 값
`partial`. 네 번째 값은 기존 필드의 의미를 바꾸므로 `docs/compatibility.md` 기준 breaking bump다. 권고는
bump와 함께 `partial`: 오늘 세 값으로 분기하는 소비자가 아니면 너무 많거나 너무 적게 듣게 되기 때문이다.
D141의 stderr 노트와 SARIF `assay/inventory-scope` 결과는 "not checked" 대신 "read: npm (3 roots), Go
(7 bin dirs); not read: Python, Java, node_modules elsewhere, Go binaries elsewhere"라고 말한다.

**차등(D93/D117).** `cmd/scandiff`의 `inventoriedTypes`에 `npm`과 `go-module`(stdlib에 대한 grype의
`go-module` 철자 포함)이 들어간다. 그 타입에 존재하는 세 `maxGrypeOnlyApp` 시드(ubi8n18 npm 82, bci156
go-module 92, cleanstart-postgres go-module 2)는 같은 PR에서 제거하고, ubi8n18/bci156/cleanstart의
floor(`maxFindings`, `maxAssayOnlyFixed`)는 브랜치의 차등 dispatch가 깨진 곳에서만 다시 심었다: archlinux
(captree의 Go stdlib finding 때문에 `maxFindings` 44 → 106, `maxAssayOnlyFixed` 25 → 84); ubi8n18,
bci156, cleanstart는 floor를 지켰다. 그 dispatch에서 측정: ubi8n18 grype 전용 41 → 0(RPM 소유 CVE 3건이
이제 두 이름 모두에서 일치), bci156 47 → 0, cleanstart 1 → 0.

**디렉터리 스캔은 바뀌지 않는다.** `dir:`는 `node_modules`를 잘라낸다(D26: 체크아웃의 설치 트리는 선언된
의존성이 아니다). 이미지 프로브는 설치 트리를 읽는데, 이미지에는 선호할 lockfile이 없기 때문이다.
DESIGN.md의 애플리케이션 패키지 불릿이 이 비대칭을 적는다.

## 범위 밖

Python `dist-info`/`egg-info`, 이미지 안의 jar, 세 루트 밖의 `node_modules`, 일곱 디렉터리 밖의 Go
바이너리, 전체 트리 walk, 설정 가능한 루트, D121/D124가 이미지 패키지에 이미 주는 것 이상의 VEX 범위.

## 테스트 (caller first, CLAUDE.md)

1. `usr/lib/node_modules/npm/package.json`과 중첩된 `node_modules/npm/node_modules/minimatch/package.json`을
   가진 합성 이미지 tar에 `minimatch` 권고를 가진 데이터베이스로 `Run`: finding이 `npm` 아래 중첩 경로로
   보고되고 `inventoryScope`가 npm read, PyPI not-read라고 말한다. 프로브 호출을 지우면 빨강.
2. 테스트가 빌드한 Go 바이너리(`gobinary`의 테스트가 하나 빌드하듯)를 `usr/bin/`에 둔 이미지와 그 stdlib
   버전에 대한 권고로 `Run`: `Go` 아래 finding; 같은 바이너리가 `opt/tool/bin/`에 있으면 아무것도 내지
   않고 `applicationScope`가 일곱 루트와 함께 Go read라고 말한다. `usr/bin`의 ELF 아닌 실행 파일은 결코
   4바이트 넘게 읽히지 않는다(D112 바이트 카운터로 단언).
3. 버전 없는 `package.json` → `summary.notEvaluated`의 원인 목록에 세어지는 skip, 패키지 없음.
4. D141 노트와 SARIF 결과가 read/not-read 목록을 싣고, 디렉터리 경로는 여전히 `inventoryScope`를 내지
   않는다.
5. `cmd/scandiff`: 타입이 인벤토리화된 뒤 npm이나 go-module `maxGrypeOnlyApp` ceiling이 거부된다는
   committed-targets 테스트.
6. 커밋 뒤 변이 라운드; 각 프로브의 호출 지점을 한 번씩 지운다.

## 같은 PR의 문서

측정과 함께 D70을 수정하는 로드맵 D160(EN/KO); D111·D141 추기; D117 추기; `docs/compatibility.md`
스키마 bump; CHANGELOG; DESIGN.md의 "Application packages inside an image" 불릿과 README의 "8개 언어
생태계" 불릿; 유보 항목을 다시 봄으로 표시(Python/Java는 열린 절반으로 남음); `CLAUDE.md`의 provider/scan
문단.
