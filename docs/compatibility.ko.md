# 호환성

`assay` 출력을 소비하는 쪽이 릴리스를 넘어 기댈 수 있는 것과 버전 증가가 뜻하는 것입니다.
`assay`는 1.0 이전이라 깨지는 변경이 아직 있을 수 있지만, 조용히 일어나지는 않습니다. 그런 변경에는
버전 증가, [변경 이력](../CHANGELOG.ko.md)의 **Breaking** 항목, 릴리스 노트의 "Compatibility" 절이
함께 따릅니다.

## 버전이 매겨진 계약

| 계약 | 무엇인가 | 버전 필드 | 현재 |
|---|---|---|---|
| `report` | `assay scan --output json` | `schemaVersion` | 14 |
| `provenance sidecar` | `--provenance <path>`가 쓰는 파일(D120) | `schemaVersion` | 1 |
| `status.json` | 배포 데이터베이스의 상태, `status` 브랜치(D138) | `schemaVersion` | 1 |
| `database` | 로컬 저장소와 OCI 태그 `ghcr.io/kun9497/assay-db:vN` | 태그 `vN`, `db status`의 `schema:` | 9 |

테스트가 이 표를 코드의 상수에 묶어 두므로, 버전이 올라도 표가 뒤처질 수 없습니다.

## JSON 리포트

**문서가 바뀔 때마다 `schemaVersion`이 오릅니다.** 선택적 필드 하나를 더할 때도 마찬가지입니다.
소비하는 쪽은 숫자만으로 "아는 형식"과 "처음 보는 것"을 가를 수 있습니다.

증가는 두 종류이며, 변경 이력이 어느 쪽인지 밝힙니다.

- **추가(Additive)**: 필드가 더해지고, 기존 필드는 이름, 타입, 의미를 모두 유지합니다. 지금까지의
  증가는 아래에 적은 예외를 빼면 모두 이 종류였습니다.
- **깨짐(Breaking)**: 필드가 제거되거나, 이름이 바뀌거나, 타입이나 의미가 바뀝니다. 지금까지 필드를
  제거하거나 이름을 바꾼 적은 없습니다.

안전하게 읽으려면:

- 모르는 필드는 무시하십시오. 새 필드는 마이너 릴리스에서 들어옵니다.
- `schemaVersion`이 한 숫자와 같은지가 아니라, 읽는 필드가 도입된 버전 이상인지를 확인하십시오.
  `== 12`로 고정한 소비자는 13에서 이유 없이 깨졌습니다.

**이력이 이에 못 미친 곳.** 오래 운영된 소비자가 기댄 것을 확인할 수 있도록 기록합니다.

- 스키마 12(v0.6.0. 11은 릴리스되지 않음)에서 `summary.targetIncomplete`가 세는 대상이 바뀌었습니다.
  D109 이후 읽지 못한 manifest를 포함합니다. 릴리스 노트는 `--fail-on-incomplete=target`이 통과하던
  곳에서 exit 2가 될 수 있다고 경고했지만, 의미가 바뀐 필드가 없다고도 적었고, 이 필드에 대해서는
  틀렸습니다.
- v0.10.0부터 이미지 OS 패키지의 `purl`이 채워집니다(D121). 이전에는 비어 있었습니다. 그 릴리스의
  14로의 증가는 `provenance` 때문이었습니다.
- 세 추가가 증가 없이 릴리스되어, 같은 `schemaVersion`의 두 릴리스가 서로 다릅니다.
  `crossMappedFrom`(D108, v0.5.0, 스키마 10), 그리고 `locations[].install`과
  `provenance.database.artifact.signedBy` / `unverified`(D137, v0.11.0, 스키마 14). 모두
  선택적입니다. 위의 규칙, 즉 모든 변경에 증가는 스키마 15부터 적용됩니다.

## provenance sidecar와 status.json

둘 다 자기 `schemaVersion`을 가지고 리포트와 같은 규칙을 따릅니다. 두 가지를 덧붙입니다.

- sidecar는 리포트의 `provenance` 객체를 담습니다. 그 객체는 sidecar가 아니라 리포트의
  `schemaVersion`에 따라 바뀌므로, 두 숫자를 모두 읽으십시오.
- `status.json`의 `published.schemaVersion`은 태그에 있는 아티팩트의 데이터베이스 스키마이지,
  `status.json` 자체의 버전이 아닙니다.

## 데이터베이스

스키마는 태그의 일부입니다. `assay db update`는 바이너리가 읽는 스키마의 `assay-db:v<N>`을 받고,
`assay db ref`가 그 태그를 출력합니다. 바이너리는 정확히 자기 스키마만 읽습니다. 제자리에서
마이그레이션하지 않습니다. 다른 스키마를 만난 스캔이나 `db status`는 exit 2로 끝나며 `assay db update`를
실행하라고 알리고, `db update`는 다른 스키마의 아티팩트를 받기 전에 거부합니다. 따라서 스키마가
오르는 업그레이드에는 `db update` 한 번이 필요합니다. CI 캐시는 `assay db ref`로 키를 만들어야
합니다([데이터베이스](DESIGN.ko.md#데이터베이스) 참고).

스키마는 v0.1.0부터 9입니다.

## SARIF

출력은 SARIF 2.1.0입니다. 자체 버전이 없으므로 안정적인 부분을 여기 적습니다.

- finding 규칙 id는 `<advisory id>-<package name>`입니다.
- 규칙 `assay/not-evaluated`, `assay/not-read`, `assay/frozen-data`, `assay/inventory-scope`는 id와
  의미를 유지합니다.
- `partialFingerprints` 키 `assay/pkg-advisory/v1`이 fingerprint 방식을 가리킵니다. fingerprint 계산
  방식의 변경은 새 키로 나가므로, 기존 code-scanning 경보가 조용히 다른 것으로 식별되지 않습니다.

## 메이저 버전 없이는 바뀌지 않는 것

- **종료 코드**(D11): `0` 깨끗함, `1` `--fail-on*` 게이트 이상인 finding, `2` 실행할 수 없었거나
  결과를 믿을 수 없음. `2`가 `1`보다 우선합니다.
- **스트림 규율**: 결과는 stdout, 진단은 stderr.
- **플래그 이름.** 플래그의 의미는 릴리스 노트와 함께 좁히거나 넓힐 수 있지만, 플래그의 이름을
  바꾸거나 없애지는 않습니다.
- **테이블 출력은 사람을 위한 것입니다.** 레이아웃은 어느 릴리스에서든 바뀔 수 있으니, JSON이나
  SARIF를 파싱하십시오.
