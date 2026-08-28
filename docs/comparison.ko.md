# assay · grype · trivy — 비교

*2026-08-27 시점 스냅샷 — assay v0.2.0, grype v6, 그리고 그날 읽은 trivy.dev 문서 기준.
assay↔grype 수치는 **실측값**입니다: 같은 digest 고정 이미지를 두 스캐너에 넣는 주간
차등(D93)의 결과입니다. trivy 열은 공식 문서 기준의 **스펙 비교**입니다 — trivy는
D105에서 주간 차등에 합류했으며(23개 타깃 중 16개, 우선 informational floors), trivy의
실측값은 첫 씨앗 실행부터 쌓여 갈 것입니다.*

## 구조와 성격

| | grype 생태계 | trivy | assay |
|---|---|---|---|
| 형태 | 세 프로젝트: syft(인벤토리), vunnel + grype-db(데이터베이스), grype(매칭) | 멀티 스캐너 하나: 취약점 + 설정 오류(IaC) + 시크릿 + 라이선스 | 취약점 전용 바이너리 하나: 인벤토리 → 매칭 → 판정 |
| 데이터베이스 | 별도 도구가 빌드·게시 | 기본값이 스캔 시 자동 다운로드 — 편리하지만 스캔 경로에 네트워크가 들어오고, 에어갭은 별도 오프라인 절차 필요 | `assay db update`가 명시적으로 당겨오고 스캔은 **절대** fetch하지 않음(D14) — SBOM·로컬 타르볼 스캔은 네트워크 호출 0회 |

## 커버리지

| 영역 | assay | grype | trivy | 비고 |
|---|---|---|---|---|
| OS 패밀리 공통부 | ✓ | ✓ | ✓ | Alpine·Debian·Ubuntu·RHEL·Rocky·Alma·Amazon·Oracle·SLES/Leap·Wolfi·Chainguard·MinimOS·Echo·Azure Linux·Photon — 셋 다 커버 |
| Fedora · Arch | ✓ (D75, D97) | ✓ | ✗ | trivy 지원 목록에 둘 다 없음 (CentOS Stream도 명시적 미지원) |
| Alpaquita · Hummingbird · CleanStart | ✓ (D95, D98, D101) | 일부만 | ✗ | grype는 Hummingbird 프로바이더 보유; Alpaquita·CleanStart는 assay 단독 |
| openSUSE Leap · SLE | ✓ | ✗ v6에 데이터 없음 | SLE ✓, Leap은 실측 공백 | SLE BCI에서 trivy는 실재하되 다른 어휘를 씁니다: finding을 SUSE-SU 패치 advisory로 키 잡고 CVE는 References URL 안에만 실어, D105 첫 측정이 "trivy가 아무것도 못 찾았다"로 오독됐다가 차등이 그 CVE를 추출하도록 배우고서야 바로잡혔습니다(추출 후 assay와 agree 182/188). Leap 15.6 이미지에서는 trivy가 진짜로 빈 취약점 목록을 반환하며(릴리스를 EOSL로 표시) assay는 12건을 보고 — 이 타깃은 정보 모드 유지 |
| Bottlerocket · CoreOS | ✗ | ✗ | ✓ | trivy 단독 |
| 언어 생태계 | 8종 | 8종 | 더 넓음 | 공통 8종(Go·npm·PyPI·crates.io·Maven·RubyGems·NuGet·Packagist); 셋 다 pnpm과 yarn berry 락파일을 읽습니다(assay는 D103부터); trivy는 여기에 더해 Conan·Dart·Swift·Elixir까지 다룹니다 |
| 보강 피드 게이트 | NVD · EPSS · KEV · EOL | NVD · EPSS · KEV · EOL | 내장 없음 | trivy는 심각도 중심 — EPSS/KEV/EOL을 게이트로 내장하지 않음 |
| KISA / KNVD | ✓ 1급 소스 | ✗ | ✗ | assay가 기존 도구 재사용 대신 존재하는 이유 |
| 취약점 외 스캔 | ✗ (의도) | ✗ (의도) | 설정오류 · 시크릿 · 라이선스 | trivy는 멀티 스캐너 — 격차가 아니라 범위의 차이 |

## 실측 패리티 — 2026-08-24 차등 (assay ↔ grype 한정)

같은 digest 고정 이미지를 두 스캐너에 넣고 튜플 단위로 비교했습니다. 이 13개 타깃은
이후 23개로 늘어 매주 CI에서 실행됩니다. trivy는 D105에서 자신이 지원하는 16개
타깃에 대해 실행에 합류했습니다; trivy의 첫 실측 floor는 지금 씨앗을 심는 중이라,
이 표는 여전히 assay↔grype 한정입니다.

| 패밀리 | 결과 | 차이의 원인 | 판정 |
|---|---|---|---|
| Alpine | 10/10 동일 | grype의 +4는 CPE 폴백 매처 산출 — assay가 의도적으로 갖지 않는 것 | 완전 일치 |
| Ubuntu | 96/96, wont-fix 15/15 | Canonical 트래커 fix state까지 정확 일치 (D85) | 완전 일치 |
| AlmaLinux | fixable 집합 동등 | — | 완전 일치 |
| Amazon · Wolfi | 0 = 0 | 다운그레이드 프로브로 비공허 검증 | 완전 일치 |
| Debian | 167 일치 | assay-only 6건은 grype DB 누락; 1건은 논쟁 여지 있는 assay FP (zlib1g/MiniZip) | assay 우세 |
| Rocky | fixable 99.4% | assay-only 2건은 결함 있는 업스트림 레코드 (RLSA-2023:6699, peridot#204로 제보) | 업스트림 결함 |
| Oracle | — | grype-only 튜플은 FIPS 계열 ELSA의 메인라인 오매칭 — assay의 거부(D79)가 옳은 쪽 | assay 우세 |
| Fedora | 30/30 (어드바이저리) | CVE 추출 격차는 양방향 — Bodhi 산문의 한계 (D75, 81.7%) | 양방향 격차 |
| openSUSE Leap | — | grype v6에 Leap 데이터 자체가 없음 | assay 단독 |
| SLES (bci-base) | 양방향 차이 | 데이터 모델 차이: assay는 affected-no-fix 108건 표현, grype는 LTSS 채널 픽스 — D91의 LTSS 병합으로 해소 | D91로 해소 |

요지: 차이의 대부분은 매처 버그가 아니라 **데이터 소스의 차이**였고, 이 작업이 찾아낸
진짜 버그 하나(D90 CSAF ID 충돌)는 수정됐습니다. 이 실측을 매주 반복하는 것이
D93입니다.

## 정책이 갈리는 곳

| 항목 | assay | grype | trivy | 맥락 |
|---|---|---|---|---|
| CPE/NVD 폴백 매처 | 없음 (의도) | 있음 | 벤더 어드바이저리 중심 | 차등에서 grype의 주요 false-positive 원천으로 분류 |
| FIPS/Ksplice/ESM 계열 | not evaluated로 보고 | 메인라인 데이터로 판정 | 구분 없음 | 맞는 데이터가 없으면 판정하지 않는다 (D53, D79) — 오라클 차등이 이 거부가 옳았음을 확인 |
| ignore 규칙 | 사유 필수 + 만료 경고 (D102) | 있음 | `.trivyignore` — CVE 나열, 사유 불요 | assay만 이유 없는 면제를 로드 단계에서 거부하고 억제를 모든 출력에 표시 |
| VEX 문서 입력 | OpenVEX 파일, `--vex` (D104) | 있음 | 4가지 방식 (repo·파일·OCI attestation·SBOM 참조) | 셋 다 OpenVEX 파일을 읽음; trivy는 repo/attestation 전달 방식을 추가로 갖춤. assay는 이유 없는 `not_affected`를 경고와 함께 건너뛰는 반면 grype는 조용히 받아들이고, 충돌하는 statement는 assay가 최신 우선으로, grype는 가장 이른 것으로 해소함 |
| 여러 소스의 등급 | 전부 보존, 최고치로 게이트 (D25) | 단일 표시 | 소스 우선순위로 하나 선택 | 19,715개 CVE 그룹 중 8,893개가 복수 레코드 — assay는 불일치 자체를 보여줌 |
| exit 코드 계약 | `2 > 1 > 0` 고정 (D11) | 유사하나 계약 명시 없음 | `--exit-code`로 사용자 지정 | assay는 "못 믿을 결과(2)"가 "발견(1)"보다 항상 우선 — CI가 고장과 clean을 혼동하지 못함 |
| 플래그 이름 | 의미가 같으면 grype와 동일 (D18) | — | 독자 체계 | 마이그레이션과 차등 스크립트를 위해 — 조용한 의미 차이는 금지 |

## assay에만 있는 것

| 항목 | 내용 |
|---|---|
| KISA/KNVD | 한국어 어드바이저리가 1급 소스; 한국어 산문 보강은 로컬 `assay db build`로 |
| 모든 소스의 등급 보존 | 두 DB가 한 CVE를 다르게 매기면 둘 다 보여주고 게이트는 최고치를 취함 (D25) — 리포트가 자기 판정과 어긋나지 않음 |
| 7개 게이트 + exit 계약 | `--fail-on`·`-unknown`·`-incomplete`·`-unfixable[=wont-fix]`·`-kev`·`-epss`·`-eol`, exit `2 > 1 > 0` (D11) |
| 불완전성의 원인 표시 | 평가 못 한 패키지는 개수+원인과 함께 skipped — clean 판정에 조용히 섞이지 않음; `--fail-on-incomplete=target`은 호출자가 고칠 수 있는 것만 게이트 (D36) |

## 출처

assay↔grype 실측과 패밀리별 분석은 [deferred-decisions.ko.md](deferred-decisions.ko.md)의
2026-08-24 차등 항목과 커버리지 재측정 항목에 있습니다. trivy 열은 2026-08-27에 읽은
[trivy.dev 문서](https://trivy.dev/latest/docs/coverage/os/) 기준입니다. 결정 ID는
[로드맵 스펙](superpowers/specs/2026-07-29-assay-roadmap.ko.md)을 가리킵니다.
