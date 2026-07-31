# assay — 아키텍처와 로드맵

*[English](2026-07-29-assay-roadmap.md) · 한국어*

**작성일:** 2026-07-29
**상태:** 합의됨. 스캐폴드의 최초 서술을 대체함.

프로젝트 전체의 기준 설계 문서입니다. 개별 슬라이스는 각자의 구현 계획을 갖고, 이 문서는 **이
시스템이 무엇이고, 왜 이런 모양이며, 어떤 순서로 만들어지는지**를 기록합니다.

미룬 작업, 알려진 함정, 미검증 가정은
[`../../deferred-decisions.ko.md`](../../deferred-decisions.ko.md)에 있습니다.

---

## 1. 목표

컨테이너 이미지, 바이너리, 디렉터리, SBOM을 받아 거기 영향을 주는 알려진 취약점을 보고하는 단일
도구. 인벤토리 생성, 취약점 데이터베이스 구축, 그리고 둘의 매칭을 모두 포함합니다.

anchore 생태계에서는 이것이 세 개의 별도 프로젝트입니다. `syft`가 인벤토리를 만들고,
`vunnel` + `grype-db`가 데이터베이스를 만들고, `grype`가 매칭합니다. assay는 셋 다 합니다.

기존 스캐너와 구별되는 지점은 둘입니다:

- **국내 취약점 데이터.** KISA/KNVD는 NVD와 OSV가 늦게 다루거나 아예 다루지 않는 소프트웨어에
  대한 권고와 KVE 식별자를 발행합니다.
- **설명 가능한 매칭.** 모든 finding이 그것을 만들어낸 근거를 함께 담습니다 — 어떤 범위,
  어떤 comparer, 어떤 비교 결과였는지.

설계 목표, 우선순위 순: **설명 가능할 것**, **오프라인 동작**, **지루한 출력**(결정적이고,
diff 가능하고, CI 친화적으로).

### 비목표

설정 오류 스캔, 시크릿 스캔, IaC, 쿠버네티스 보안 태세 — trivy가 확장해 간 방향들입니다. 취약점
매칭과 공유하는 코드가 거의 없어서, 포함한다는 건 **같은 바이너리 안에 다른 도구를 하나 더 넣는
것**과 같습니다.

---

## 2. 결정들

각 결정은 근거를 함께 기록합니다. 근거가 있어야 나중에 개정할 수 있기 때문입니다.

### D1 — OSV를 정규화 대상으로 삼는다

권고는 OSV 형태로 저장합니다. `affected[].ranges[]`가 `introduced` / `fixed` 이벤트를 담습니다.

대안은 업스트림 피드를 직접 수집해 우리가 정규화하는 것이었습니다(NVD의 CPE match 범위, OVAL
조건 트리, 배포판 secdb 포맷 등). **소스마다 범위 표현이 다르고, 정규화 계층이 스캐너보다
커집니다.** anchore가 `vunnel`과 `grype-db`를 별도 리포지터리로 분리한 이유가 이것입니다.

검증된 정규화 대상을 재사용하는 편이 새로 만드는 것보다 낫습니다. OSV는 언어 생태계 커버리지도
강한데, 첫 슬라이스가 바로 거기입니다.

grype의 사전 빌드 데이터베이스를 읽는 방안은 배제했습니다. 그 스키마는 anchore의 내부 계약이라
메이저 버전마다 바뀌고, 결정적으로 **우리가 소유하지 않은 스키마에는 우리 소스를 넣을 수
없습니다.** KISA가 이 안을 탈락시킵니다.

### D2 — Provider 추상화를 첫날부터 둔다

KNVD 데이터가 OSV 형식으로 오지 않을 것이므로 수집과 정규화가 어느 정도는 불가피합니다.
`Provider` 인터페이스를 두면 OSV는 거의 통과에 가까운 구현체가 되고 KISA는 두 번째 구현체가
됩니다. 모든 업스트림 피드를 직접 만드는 데 발을 담그지 않고도요.

### D3 — KISA는 매칭 소스가 아니라 우선 보강이다

OSV로 매칭된 finding이 CVE ID 조인을 통해 한국어 설명, KISA 심각도, KNVD 링크를 가져옵니다.
KVE 항목이 자체적으로 finding을 만들지는 않습니다.

**조인은 `aliases`와 `upstream`을 모두 읽어야 합니다.** OSV 1.7 레코드는 CVE 링크를 `aliases`가
아니라 `upstream`에 담습니다. 표본으로 확인한 Alpine 레코드는 `"upstream":["CVE-2006-20001"]`을
갖고 `aliases`는 아예 없었습니다. 한 필드만 읽으면 **조인이 조용히 실패합니다.** 보강에서는 이게
최악의 실패 양상입니다 — finding은 그냥 한국어 데이터 없이 나타나고, 아무것도 오류를 보고하지
않습니다.

KNVD 권고 상당수가 국산 상용 소프트웨어를 산문으로 기술합니다. 생태계도, purl도, 패키지 이름도
없습니다. 패키지 매칭이 아니라 CPE식 *제품* 매칭이죠. 현재 타깃과도 안 맞습니다. 컨테이너
이미지와 소스 트리에 한컴오피스는 없으니까요. 승격 경로를 기록해 둔 채 미룹니다.

### D4 — 로컬 저장소는 bbolt

접근 패턴은 `(ecosystem, name)`에 의한 점 조회이고, 패키지 수만큼 반복됩니다. range scan도,
join도, 집계도 없습니다. **순수 key-value이고 SQL이 사줄 것이 없습니다.**

Makefile의 `CGO_ENABLED=0`이 `mattn/go-sqlite3`를 배제합니다. 남는 SQLite 선택지인
`modernc.org/sqlite`는 C를 Go로 기계 번역한 것이라, **`require` 블록이 아예 없는 `go.mod`에
넣기엔 매우 큰 의존성**입니다.

SQLite의 실질적 우위는 디버깅 하나입니다(개발 중 `sqlite3 db "select ..."`). 그건 `assay db
inspect`로 회수할 수 있고, 어차피 계획된 explain 모드와 겹칩니다. trivy도 같은 접근 패턴에서 같은
판단을 했습니다.

`Store`가 작은 인터페이스라, 이 판단이 틀렸다면 되돌릴 수 있습니다.

### D5 — 경로에 스키마 버전을 둔다

`<cache>/assay/db/v2/vulnerability.db`. 스키마가 바뀌면 마이그레이션 코드를 쓰는 대신 새
디렉터리에 다시 빌드합니다. **사용자가 한 명인 프로젝트에서 마이그레이션 코드는 부채입니다.**

### D6 — 배포판 패키지는 릴리스를 키에 포함한다

생태계 키는 `Alpine`이 아니라 `Alpine:v3.19`입니다. 패키지의 수정 버전이 릴리스마다 다르므로
릴리스가 조회 키의 일부입니다. OSV가 배포판 데이터를 분할하는 방식과도 일치합니다.

### D7 — 배포판은 패키지가 아니라 타깃에 속한다

*이미지*가 Alpine 3.19인 것이지 그 안의 패키지가 그런 게 아닙니다. `Target.Distro`는
`/etc/os-release`에서 한 번 읽어 내부의 모든 OS 패키지에 적용됩니다.

### D8 — `Package.Source`가 소스 패키지를 담는다

배포판 권고는 **소스** 패키지 기준으로 작성되지만 설치된 것은 **바이너리** 패키지입니다:

```
advisory:  source package  openssl     < 1.1.1n-0+deb11u3   vulnerable
installed: binary package  libssl1.1     1.1.1n-0+deb11u1
```

`libssl1.1`을 조회하면 아무것도 안 나옵니다. 매칭하려면 그것의 소스가 `openssl`이라는 걸 알아야
합니다. 이게 없으면 실패는 오탐이 아니라 **미탐**입니다 — 조용하고 훨씬 위험합니다. grype의 dpkg
matcher에서 가져왔습니다.

**이건 Debian과 RHEL만이 아니라 Alpine에도 적용됩니다.** 표본 OSV 레코드가
`"purl":"pkg:apk/alpine/apache2?arch=source"`를 담고 있습니다. Alpine 권고도 소스 기준입니다.
Alpine이 첫 배포판(슬라이스 2)이므로, **간접 매칭은 나중 배포판 작업으로 미룰 수 있는 게 아니라
거기서 필요합니다.**

채우는 방법은 cataloger마다 다릅니다. dpkg는 `/var/lib/dpkg/status`에 `Source:`를, apk는
`/lib/apk/db/installed`에 `o:`(origin)를 노출합니다.

### D9 — 버전 비교는 생태계별로 유지한다

Debian의 epoch, RPM의 release 순서, semver의 pre-release 우선순위, Maven의 정렬 규칙이 실제로
서로 어긋납니다. 공유 `compareVersions`는 이 설계가 피하려는 바로 그 버그입니다.

`Comparer`는 `int`이 아니라 `(int, error)`를 반환합니다. 실제 시스템의 버전 문자열은 때때로 형식이
깨져 있고, **파싱 불가능한 버전을 조용히 "취약하지 않음"으로 처리하면 그것이 미탐입니다.** 에러는
건너뛴 패키지와 그 개수로 표면화되며, 절대 클린 결과가 되지 않습니다.

### D10 — `Finding`이 `Evidence`를 담는다

설명 가능성이 목표 1번입니다. 근거가 타입 안에 없으면 로그 줄에 흩어지고, 그건 사실상 없는
것입니다.

### D11 — 종료 코드 우선순위는 계약이다

```
2 (could not run / cannot be trusted)  >  1 (findings at or above --fail-on)  >  0 (clean)
```

**신뢰할 수 없는 결과가 결과의 내용보다 우선합니다.** 종료 코드는 CLI 계약이라 나중에 바꾸면 남의
CI가 깨집니다. 그래서 이를 필요로 하는 강제 기능이 미뤄져 있음에도 지금 고정합니다.

### D12 — 신선도는 로컬 빌드 시각이 아니라 업스트림 데이터로 잰다

`Provenance.DataAsOf`가 **업스트림 데이터가 언제 기준인지**를 기록하며, 이는 로컬 데이터베이스를
조립한 시각인 `Meta.BuiltAt`과 별개입니다.

빌드 시각은 엉뚱한 것을 잽니다. 3개월 된 스냅샷을 서빙하는 미러에서 오늘 받아오면 빌드 시각은
오늘이 되고, 빌드 시각 기반 신선도 검사는 **한 분기 묵은 데이터를 최신이라고 보고합니다.**
에어갭 동작은 명시된 목표이지 예외 케이스가 아니므로, 이건 첫 빌드부터 맞아야 합니다.

나이 *강제*는 미뤘지만, 그것을 가능하게 하는 메타데이터는 미루지 않았습니다. 나중에 추가하려면
데이터베이스를 다시 빌드해야 하기 때문입니다.

### D13 — Provider는 업스트림 레코드를 무손실로 저장하고, 파생값은 조회 시점에 계산한다

예를 들어 심각도 밴드는 빌드 시점에 박아 넣는 대신 저장된 CVSS 벡터에서 뽑습니다. 이러면 **"지금
필요한 필드를 저장 안 했으니 데이터베이스를 다시 빌드하자"는 상황이 대부분 사라집니다.** 이 규모에서
저장 용량은 제약이 아닙니다.

### D14 — 스캔 경로는 절대 네트워크를 건드리지 않는다

`assay db update`만이 네트워크가 필요한 명령입니다. 데이터베이스가 없거나 스키마가 맞지 않으면
안내와 함께 종료 코드 2를 냅니다. **자동 다운로드도, 조용한 빈 결과도 없습니다.**

### D15 — 악성 패키지 신고는 제외하되, `Advisory.Kind`는 제외하지 않는다

OSV에는 `MAL-*` 레코드가 있습니다. 패키지가 취약점을 포함한다가 아니라 패키지 자체가
**악성코드**라는 신고입니다. 실제 덤프로 측정한 결과 데이터의 압도적 다수를 차지합니다
(§3의 *측정된 데이터 규모* 참조).

제외하면 슬라이스 1 데이터베이스가 약 430 MB에서 약 86 MB로 줄어듭니다.

지금 제외하는 이유는 중요하지 않아서가 아니라 **성격이 다른 finding 클래스**이기 때문입니다.
CVSS 심각도가 없으므로 `--fail-on`이 아무 의미를 갖지 못하고, 올바른 보고는 심각도 밴드가 아니라
"지금 제거하라"입니다. 제대로 지원한다는 건 두 번째 finding 클래스를 설계한다는 뜻이고, 그건
슬라이스 1의 일이 아닙니다.

`Advisory.Kind`는 그럼에도 지금 넣습니다. 필드를 나중에 추가하면 데이터베이스를 다시 빌드해야
하니까요. Provider가 이 값을 설정하고, 현재 필터는 `KindVulnerability`가 아닌 것을 전부 버립니다.

**이건 저장 용량을 아끼는 것이지 대역폭을 아끼는 게 아닙니다.** OSV는 생태계당 아카이브 하나를
서버 측 필터링 없이 제공하므로, `db update`는 여전히 슬라이스 1 기준 약 244 MB를 받아서 파싱 후
대부분을 버립니다.

### D16 — 철회된 권고는 수집 시점에 거른다

OSV 레코드에는 철회를 표시하는 선택적 `withdrawn` 타임스탬프가 있습니다. 측정한 Go 덤프에서
8,617건 중 107건(1.2%)이 철회 상태였고, `MAL-*` 4,000건 표본에서는 52건이었습니다. 이를 수집하면
**더 이상 유효하지 않은 권고에 대한 finding**이 생깁니다. 그냥 오탐입니다.

매처가 조회 시점에 건너뛰는 대신 **Provider가 수집 시점에 버립니다.** 그래야 확인을 빠뜨린 코드
경로로 철회된 권고가 새어 나갈 수 없습니다.

### D17 — "unknown"은 일급 심각도 밴드다

**Go 레코드 8,617건 중 4,335건(50.3%)에 `severity` 필드가 아예 없습니다.** 이건 대충 덮을 예외
케이스가 아니라 **데이터의 절반**입니다.

없는 심각도를 `low`나 `none`으로 조용히 바꾸면 **데이터의 공백이 빌드 통과로 바뀝니다.**
`unknown`은 `low < medium < high < critical` 순서의 맨 아래가 아니라 **그 바깥**에 있는 독립
밴드입니다.

여기서 세 가지 동작이 따라 나오며, 세 번째가 존재하는 이유는 앞의 둘로는 부족하기 때문입니다:

1. **unknown finding은 항상 보고됩니다.** 심각도 임계값은 무엇이 빌드를 실패시킬지를 정할 뿐,
   무엇이 출력에 나타날지는 절대 정하지 않습니다.
2. **unknown은 `--fail-on <밴드>` 만으로는 트립하지 않습니다.** 전체 권고의 절반이 미평가인
   상황에서 반대로 하면 모든 스캔에서 발동해 플래그가 무용지물이 됩니다.
3. **`--fail-on-unknown`이 이를 명시적으로 게이팅합니다.** 이게 없으면 (1)과 (2)를 합쳐도 평가되지
   않은 critical 취약점이 여전히 0으로 통과합니다 — 출력에는 찍히지만 통과입니다. 이는 `low`로
   떨어뜨리는 것과 같은 실패이고, 단지 더 시끄러울 뿐입니다. 기본을 켜두면 (2)의 문제를 그대로
   재현하므로 옵트인입니다.

```bash
assay scan img --fail-on high                      # unknown passes; count shown in summary
assay scan img --fail-on high --fail-on-unknown    # unknown also exits 1
```

unknown 개수는 두 출력 경로 모두에 **조건 없이** 들어갑니다. **판단하지 못한 양을 숨기는 임계값은
임계값이 아닙니다.**

심각도가 있는 경우 그것은 CVSS 벡터입니다. Go 덤프에는 `CVSS_V3`(3,688)와 `CVSS_V4`(1,100)가 모두
있으므로 파서는 처음부터 둘 다 처리합니다 — 그리고 D13에 따라 벡터를 저장하고 밴드는 조회 시점에
계산합니다.

**50%라는 수치가 영구적이지 않을 수 있습니다.** CVSS 벡터가 없는 레코드도 NVD가 점수를 매긴 CVE를
alias로 갖는 경우가 흔합니다. NVD 심각도를 보강 소스로 조인하면 — KISA와 같은 메커니즘(D3) —
상당 부분을 채울 수 있습니다. 계획이 아니라 가능성으로 기록해 둡니다.

### D18 — CLI 플래그 이름은 의미가 같은 한 grype를 따른다

`--fail-on`, `--output` 등의 이름을 grype와 공유하는 것은 **의도적**입니다. 플래그 명명은 거의
장르 관례에 가깝고, 마이그레이션하는 사람에게 익숙함이 그대로 이어지며, 주 정확성 검증 수단인
대조 테스트(§5)가 **두 도구가 같은 인자를 받을 때 스크립트로 짜기 쉽습니다.**

여기서 생기는 위험은 공유된 이름 자체가 아니라 **공유된 이름 아래의 다른 동작**입니다. assay가
다른 지점은 발견하도록 방치하지 않고 문서화합니다:

| 플래그 | grype와의 차이 |
|---|---|
| `--fail-on-unknown` | grype에 대응물 없음. assay의 심각도 순서 바깥에 unknown이 있기 때문에 존재함(D17). |

공유된 이름이 다른 의미를 갖게 될 때마다 이 표에 행을 추가하십시오. **조용히 달라진 플래그가
이름이 다른 플래그보다 나쁩니다.**

---


### D19 — 레지스트리 접근은 `go-containerregistry`, 레이어 내용은 우리 것

두 번째 서드파티 의존성. 양쪽을 측정한 뒤 의도적으로 채택했습니다.

**직접 짜면 실제로 얼마나 드는가.** Docker Hub 익명 pull은 요청 세 번입니다 —
`WWW-Authenticate` 챌린지를 담은 `401`, 그 챌린지가 지목한 realm에서 토큰 받기, 베어러
헤더를 붙인 매니페스트 재요청 — 그리고 이걸 그대로 하는 stdlib 판은 93줄입니다. 이 숫자
때문에 직접 짜는 게 싸 보였고, 그것이 오해였습니다. 레지스트리 하나, 익명, happy path일
뿐입니다. 세 곳을 재보니 이미 세 갈래로 갈립니다 — Docker Hub는 `auth.docker.io`에서
2,658자 토큰을, GHCR은 자기 호스트에서 52자 토큰을 주고, Quay는 공개 매니페스트에 챌린지
자체가 없습니다. 재시도, 레지스트리의 `Authorization` 헤더를 거부하는 CDN으로의 blob
리다이렉트, 레지스트리별 에러 분류, 그리고 **설정 파일이 아니라 stdio로 대화하는 별도
실행 파일**인 credential helper — 이 전부가 그 93줄에 없습니다.

**채택하면 얼마나 드는가.** 링크되는 모듈 9개, 패키지 46개, 바이너리 6.3 MB → 6.8 MB.
`go.sum`은 47개 늘지만 그중 38개는 의존성의 테스트·툴링 의존성(`cobra`, `blackfriday`,
`opentelemetry`, `testify`)이라 **아무것도 컴파일되지 않습니다.** 이 구분이 중요합니다 —
실행 코드가 아니라 빌드 시점 공급망 표면입니다.

`docker/cli`와 `docker-credential-helpers`는 익명 전용으로 써도 링크됩니다. 즉 프라이빗
레지스트리 자격증명이 나중 작업이 아니라 의존성과 함께 들어옵니다. 이것이 결정적입니다 —
직접 짤 때 비싼 쪽이 자격증명 해석이었는데, 라이브러리를 쓰면 그 절반이 통째로 사라집니다.

**경계.** 의존성이 사주는 것은 레지스트리 프로토콜과 인증뿐입니다. 레이어 순회, whiteout
적용, `/etc/os-release`와 `/lib/apk/db/installed` 파싱은 우리 것으로 남습니다 — 이 프로젝트가
소유하려는 부분이고, 어차피 어떤 라이브러리도 대신 해주지 않습니다.

**레이어 내용은 디스크에 쓰지 않습니다.** 스캔에 필요한 것은 레이어당 파일 두 개뿐이므로
레이어를 스트리밍하며 원하는 항목만 지나가는 길에 읽습니다. path traversal, symlink 탈출,
아카이브 폭탄은 **추출** 취약점입니다. 추출하지 않으면 방어하는 것이 아니라 클래스가
사라집니다.

**Docker 데몬 소스는 제외합니다**(`docs/deferred-decisions.md` 참조). 이것 하나가 링크
모듈을 9 → 27개, 패키지를 46 → 114개로 만듭니다. 그리고 네 소스 중 가장 덜 필요합니다 —
로컬에 이미 있는 이미지는 `docker save`로 넘기면 tarball 소스가 읽습니다.

## 3. 아키텍처

### 측정된 데이터 규모

2026-07-29에 실제 OSV 덤프로 측정. 이 수치들이 D4(bbolt), D15(`MAL-*` 제외), D17(미평가 심각도)이
서 있는 근거입니다. 그중 어느 것이든 재검토하기 전에 **다시 측정하십시오.**

| 생태계 | 취약점 레코드 | 크기 | `MAL-*` 레코드 | 크기 |
|---|---:|---:|---:|---:|
| Go | 8,599 | 22.1 MB | 18 | 0.0 MB |
| npm | 7,004 | 19.2 MB | 216,865 | 323.2 MB |
| PyPI | 13,010 | 44.9 MB | 11,579 | 20.1 MB |
| **슬라이스 1 합계** | **28,613** | **86.2 MB** | **228,462** | **343.3 MB** |

크기는 비압축 JSON 기준입니다. 슬라이스 1의 압축 다운로드는 필터링 여부와 무관하게 약 244 MB.

이후 슬라이스용: Alpine 4,401건(압축 3.8 MB), Debian 압축 64 MB, Ubuntu 압축 570 MB.
46개 생태계 전체는 대략 압축 1.5 GB.

권고 28,613건에 86 MB라면 bbolt + JSON 값이 여유 있게 들어갑니다. 필터링하지 않은 257,075건
430 MB라도 동작합니다 — **어느 쪽이든 이 결정에는 상당한 여유가 있습니다.**

**OSV에 Red Hat 데이터가 존재합니다**(압축 25 MB). RHEL 데이터가 없거나 무시할 만하다는 이전
가정과 배치됩니다. 정확한 RHEL 매칭에 필요한 만큼 백포트를 반영하는지는 별개 문제이며, 그 작업을
시작할 때까지 미해결로 둡니다.

### 파이프라인

```
target (image | binary | dir | SBOM file)
  │
  ├─▶ Source      open the target for file access; carries layer provenance
  ├─▶ Cataloger   files → []Package, one per ecosystem
  ├─▶ Target{Distro, []Package}          ◀── normalized inventory
  ├─▶ Matcher     Package × Store → Finding, using per-ecosystem Comparer
  ├─▶ Enricher    join KISA data by CVE ID
  └─▶ Reporter    table / JSON / SARIF, --fail-on
```

데이터베이스는 이 흐름과 직교하며 스캔 중에는 읽기 전용입니다:

```
Provider(OSV)  ─┐
                ├─▶ []Advisory ─▶ Store          written only by `assay db update`
Provider(KISA) ─┘                    ▲
                                     └── Matcher reads
```

### 인터페이스

| 인터페이스 | 책임 | 구현체 |
|---|---|---|
| `Source` | 타깃을 열어 파일 접근 제공 | image, dir, file, binary |
| `Cataloger` | 파일 → `[]Package` | apk, dpkg, cyclonedx, go-mod, go-binary, npm, jar |
| `Store` | 권고 조회 | bbolt |
| `Comparer` | 한 생태계 안에서의 버전 순서 | semver, PEP 440, apk, deb, rpm |
| `Provider` | 업스트림 피드 → `[]Advisory` | OSV, KISA |

새 생태계를 지원한다는 것은 `Cataloger` 하나와 `Comparer` 하나를 쓰는 것입니다. 나머지는 바뀌지
않습니다 — **이 분해 전체가 존재하는 이유가 바로 그 성질입니다.**

```go
type Store interface {
    Lookup(ecosystem, name string) ([]Advisory, error)
    LookupBySource(ecosystem, sourceName string) ([]Advisory, error)  // D8
    Enrichment(id string) (*Enrichment, error)
    Meta() (Meta, error)
    Close() error
}

type Comparer interface {
    Compare(a, b string) (int, error)  // D9
}

type Provider interface {
    Fetch(ctx context.Context) ([]Advisory, Provenance, error)
}
```

### 핵심 타입

```go
type Target struct {
    Distro   *Distro    // from /etc/os-release; nil for language-only targets  (D7)
    Packages []Package
}

type Package struct {
    Name, Version, Type string        // Type: apk | deb | golang | npm | pypi | maven
    PURL      string
    Source    *SourcePackage          // source package, for indirect matching  (D8)
    Locations []Location              // which file and layer it came from
}

type Advisory struct {                // OSV shape  (D1)
    ID       string                   // CVE-… | GHSA-… | GO-… | ALPINE-… | KVE-…
    Aliases  []string                 // OSV `aliases`  ─┬─ both carry the CVE↔KVE join (D3)
    Upstream []string                 // OSV `upstream` ─┘
    Source   string                   // "osv" | "kisa" — provider provenance
    Kind     Kind                     // vulnerability | malicious  (D15)
    Affected []Affected
    Severity []Severity               // stored as CVSS vectors, banded at query time (D13)
}

type Affected struct {
    Ecosystem string                  // "Go" | "Alpine:v3.19"  (D6)
    Name      string
    Ranges    []Range                 // introduced / fixed events
}

type Finding struct {
    Package  Package
    Advisory Advisory
    Evidence Evidence                 // which range, which comparer, what result  (D10)
}
```

### 저장소 레이아웃

```
<os.UserCacheDir()>/assay/db/v2/vulnerability.db      override: ASSAY_DB_DIR

buckets:
  advisories   "<ecosystem>\x00<name>"     → []AdvisoryID  primary lookup
  by-source    "<ecosystem>\x00<source>"   → []AdvisoryID  indirect matching (D8)
  by-id        "<advisory-id>"             → Advisory      the record itself, stored once
  enrichment   "<cve-id>"                  → Enrichment    KISA (D3)
  meta         "schema" | "built-at" | "providers"
```

**조회 버킷은 레코드가 아니라 권고 ID를 담습니다.** 한 권고가 여러 패키지에 영향을 주는 일이
흔합니다 — Go 덤프 측정 결과 8,510건 중 1,452건이 둘 이상의 패키지를 지목하고, 최대 22개입니다 —
그래서 패키지를 키로 레코드를 직접 저장하면 같은 것이 반복 저장됩니다. 측정된 증가율은 1.44배이고,
`by-id`가 자체 사본을 갖는 것까지 합치면 순진한 레이아웃은 21.9 MB 데이터를 53.6 MB로 만듭니다.
ID를 `by-id`로 해석하는 데 점 조회가 한 번 더 들지만 마이크로초 단위입니다.

| OS | 경로 |
|---|---|
| Windows | `%LocalAppData%\assay\db\v1\` |
| macOS | `~/Library/Caches/assay/db/v2/` |
| Linux | `~/.cache/assay/db/v2/` (`XDG_CACHE_HOME` 존중) |

값은 JSON으로 시작합니다. 스캔당 수백 번 조회 기준으로 bbolt 읽기는 마이크로초이고 디코딩이
지배적이지만 그래도 수십 밀리초 수준입니다. 인코딩은 `Store` 뒤에 가려져 있어 호출자를 건드리지
않고 바꿀 수 있습니다.

`db update`는 임시 파일에 빌드한 뒤 실행 중인 데이터베이스 위로 rename하므로, 동시에 도는 스캔이
부분 기록을 보지 않습니다. **Windows에서는 대상이 열려 있으면 rename이 실패합니다** — 알려진 함정
문서 참조.

---

## 4. 전달 슬라이스

아키텍처 계층이 아니라 **동작하는 경로**를 따라 잘랐습니다. 계층 하나만으로는 실행할 수 없고,
실행할 수 없는 설계는 검증할 수 없습니다.

### 슬라이스 1 — 매칭 코어 ← 첫 구현 계획 대상

```
CycloneDX SBOM ──▶ Package ──▶ Store(bbolt) ──▶ Matcher ──▶ table
                                   ▲
                           OSV provider (Go / npm / PyPI)
```

**완료 기준**

- `assay db update`가 OSV 언어 생태계 덤프로 로컬 데이터베이스를 빌드한다
- `assay db status`가 provider별 `DataAsOf`와 레코드 수를 출력한다
- `assay scan sbom.cdx.json`이 매칭된 CVE를 table로 출력한다
- 데이터베이스가 없으면 안내와 함께 2로 종료한다 — 빈 클린 결과를 내지 않는다
- `Comparer`가 semver와 PEP 440 엣지 케이스를 다루는 표 기반 테스트를 갖는다
- 같은 SBOM에 대한 grype 대조 검증(§5)

**여기서 확정되는 것:** 핵심 타입 전체, `Store` / `Comparer` / `Provider` 인터페이스, 종료 코드
우선순위, 출처 기록.

### 슬라이스 2 — 컨테이너

`assay scan alpine:3.19`. 레지스트리 pull → 레이어 추출 → `/etc/os-release` →
`/lib/apk/db/installed` → `Alpine:vX.Y` 조회.

**설계 리스크가 가장 큽니다.** `Target.Distro`, 릴리스가 포함된 생태계 키, `Location`의 레이어
출처가 전부 여기서 처음 현실과 만납니다. 늦추지 않고 앞에 두는 이유가 그것입니다 — **설계가
틀렸다면 빨리 아는 편이 쌉니다.**

**완료 기준:** Alpine 이미지가 끝에서 끝까지 스캔되고, 레이어 digest가 `Location`에 나타나고,
apk `Comparer`가 표 기반 테스트를 통과하고, grype 대조가 성립할 때.

### 슬라이스 3 — 파일시스템과 바이너리 타깃

`debug/buildinfo`(표준 라이브러리만)를 통한 `assay scan ./bin/assay`, 그리고 `go.mod`를 통한
`assay scan dir:./project`.

**어디든 끼워 넣을 수 있습니다.** 슬라이스 2에도 4에도 의존하지 않고, 비용이 매우 작으면서
`Source` / `Cataloger` 추상화를 두 번째 구현체로 검증합니다. 슬라이스 2가 막히면 이쪽이
우회로입니다.

**완료 기준:** assay가 자기 자신의 바이너리를 스캔할 때.

### 슬라이스 4 — 판정과 출력

`--fail-on`, `--fail-on-unknown`, JSON / SARIF, explain 모드. **종료 코드 1이 처음으로 도달
가능해지는 지점입니다.** 저장된 CVSS 벡터로부터의 심각도 밴드 계산이 여기 들어오며(D13), 슬라이스
1이 아직 쓰지 않는 벡터를 저장해 두는 이유가 이것입니다.

**완료 기준:** 출력이 결정적이고 diff 가능하며, explain 모드가 특정 finding의 `Evidence`를 출력할
때.

### 슬라이스 5 — KISA 보강

KNVD provider → `enrichment` 버킷 → CVE ID 조인 → 리포트의 한국어 설명과 심각도.

**선행 조건에 막혀 있습니다:** KNVD가 기계 판독 가능한 인터페이스를 제공하는지, 그리고 그 약관이
재배포를 허용하는지 확인해야 합니다. 이 미지수 때문에 마지막입니다 — **해결되지 않아도 앞의 네
슬라이스는 그 자체로 성립합니다.**

---

## 5. 검증

**grype와의 대조 테스트가 주 정확성 검증 수단**이며, 매 슬라이스마다 반복합니다. 같은 SBOM 또는
이미지를 두 도구에 넣고 결과를 비교합니다.

완전한 일치는 기대하지 않습니다. 데이터 소스가 다르니까요. 신호는 **차이의 크기**입니다. 큰 차이가
난다면 우리 매처가 틀린 것입니다. **가장 싸면서 가장 강한 정답지**이고, 돌리는 데 비용이 들지
않습니다.

그 외:

- `Store`가 인터페이스이므로 `Matcher`는 인메모리 fake로 테스트합니다 — 매칭 로직을 검증하는 데
  데이터베이스가 필요 없습니다.
- **`Comparer`의 테스트 밀도가 가장 높아야 합니다.** 생태계별 표 기반으로 deb epoch, apk `-rN`
  접미사, semver pre-release 우선순위, PEP 440 `.post` / `.dev`를 다룹니다. **여기가 미탐의
  발원지입니다.**
- bbolt 구현체는 작은 fixture 데이터베이스로 별도 테스트합니다.

---

## 6. 벤치마킹 노트

기존 도구에서 가져온 설계 요소와, 남겨둔 것.

**trivy에서**

- 데이터베이스를 OCI 아티팩트로(`ghcr.io`) — 레지스트리 배포를 쓰면 미러링·인증·에어갭 대응이
  공짜로 따라옵니다. *미룸. deferred-decisions 참조.*
- 로컬 store로 bbolt — 같은 접근 패턴, 같은 결론. *채택(D4).*
- 선택적 데이터를 별도 아티팩트로 분리(`trivy-java-db`) — KISA 데이터에 대응됩니다. *미룸.*
- 수집한 업스트림 데이터를 git에 커밋(`vuln-list`)해 감사 추적 확보. *미룸.*
- **가져오지 않은 것:** 설정·시크릿·IaC·쿠버네티스 스캔으로의 범위 확장.

**grype에서**

- 소스 패키지를 통한 간접 매칭. *채택(D8) — 이건 미탐을 막는 것이라 처음부터 들어갑니다.*
- 스키마 버전을 디렉터리로, 마이그레이션 대신 재빌드. *채택(D5).*
- assay는 인벤토리까지 만들지만, 내부 경계는 "SBOM in, findings out"의 깔끔함을 따름.
  *채택 — §3의 모양이 그것입니다.*
- **가져오지 않은 것:** 우리가 소유하지 않은 데이터베이스 스키마에 의존하는 것. 그러면 KISA가
  막힙니다.

---

## 7. 관련 문서

- [`README.ko.md`](../../../README.ko.md) — 사용자 대상 설명
- [`CLAUDE.md`](../../../CLAUDE.md) — Claude Code 세션용 작업 제약
- [`docs/deferred-decisions.ko.md`](../../deferred-decisions.ko.md) — 미룬 작업, 알려진 함정,
  미검증 가정
