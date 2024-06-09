# 웹 사이트 차단 NW 도구 개발

Linux 환경에서 C언어와 libpcap을 이용해 ARP Spoofing을 통해 같은 서브넷의 디바이스를 대상으로
</br>
특정 웹 사이트 접속을 차단하는 도구입니다.

</br>

---

## 목차
1. [사용법](#1-사용법)
2. [예시](#2-예시)
3. [동작 방식](#3-동작-방식)
4. [코드 구성](#4-코드-구성)

</br>

---
## 1. 사용법
```
./bin/HTTP_BLOCK [네트워크 인터페이스]
```

</br>

---

## 2. 예시



</br>

---
## 3. 동작 방식
### 3-1. 패킷 탐지
```
1. 해당 서브넷의 모든 디바이스에게 ARP Spoofing을 수행.
2. 새로운 디바이스가 연결되면 DHCP 패킷을 감지해 ARP Spoofing을 수행.
3. HTTP 패킷은 Host 헤더를 파싱해 비교.
4. HTTPS 패킷은 TLS ClientHello 패킷의 SNI 필드를 파싱해 비교.
```
### 3-2. 세션 차단
```
1. TCP-FIN : 디바이스한테는 차단 문구를 전달하기 위해 해당 패킷을 만들어 보냄.
2. TCP-RST : 서버한테는 바로 세션을 종료시키기 위해 해당 패킷을 만들어 보냄.
```

</br>

---
## 4. 코드 구성
### 4-1. 소스 파일
```
- ./src/*.cpp : 실질적 기능을 담당하는 소스 파일 (함수)
- ./src/protocolHeader.h : 사용하는 프로토콜 구조체에 대한 정의
- ./src/srcLinkHeader.h : 각 소스파일에 있는 함수들의 선언
- ./src/threadArgsHeader.h : 스레드를 생성 시, 변수 공유를 위한 구조체 정의
```
### 4-2. 스레드 구성
```
- Main Thread (main 함수)
1. 패킷 수신 및 파싱 (ARP Reply, TCP, UDP 수신)
2. TCP 패킷 차단 (TCP FIN, TCP RST 송신)
3. 패킷 릴레이 (VICTIM ↔ GW 간 패킷 릴레이)

- Sub Thread 1 (arpScan 함수)
1. 디바이스 IP, MAC 스캐닝 (ARP Request 패킷 송신)

- Sub Thread 2 (arpSpoofing 함수)
1. 디바이스 ARP 테이블 오염 (ARP Reply 패킷 송신)
```

