#!/bin/bash

curl -X POST http://localhost:1323/submit/1 -H "Content-Type: application/json" -d '{"code": "I2luY2x1ZGUgPHN0ZGlvLmg+CgppbnQgbWFpbigpIHsKICAgIGludCBhLCBiOwogICAgc2NhbmYoIiVkICVkIiwgJmEsICZiKTsKCiAgICBwcmludGYoIiVkIiwgYSAtIGIpOwoKICAgIHJldHVybiAwOwp9"}'