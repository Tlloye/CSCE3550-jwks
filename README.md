# CSCE 3550 - Project 1
## RESTful JWKS Server with RS256 JWT Authentication

This project implements a RESTful JWKS server in C++.

Features:
- RS256 signed JWT issuance
- Expired JWT issuance
- JWKS endpoint that filters expired keys
- Proper HTTP method handling (405 for invalid methods)
- Automated Python test suite
- 90%+ test coverage

---

## Build

Compile normally:

g++ jwks.cpp -o jwks -std=c++17

Compile with coverage:

g++ jwks.cpp -o jwks -std=c++17 --coverage

---

## Run Server

./jwks

Server runs at:
http://localhost:8080

---

## Endpoints

GET /
Health check

GET /.well-known/jwks.json
Returns non-expired public keys

POST /auth
Returns valid JWT

POST /auth?expired=true
Returns expired JWT

GET /auth
Returns 405

---

## Run Tests

python3 -m unittest discover -v

---

## Coverage

gcov jwks.cpp

Coverage result: 90%+

